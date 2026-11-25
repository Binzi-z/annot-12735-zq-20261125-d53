"""Replay-determinism fuzz: random but valid operation streams must replay
identically from the journal, and the independent auditor must agree.

This targets the subtle risk that revocation's incremental index (which
messages a given agent co-signed) is built in the same order on replay as it
was live.  Any drift would surface as a replay divergence or an audit mismatch.
"""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from tests.support import SEED, make_message, setup_link
from trustrelay.model import S_ACCEPTED
from trustrelay.state import RelayRuntime
from trustrelay.verify import audit_store, compare_with_runtime

AGENTS = [("a", "srcA"), ("b", "srcB"), ("c", "srcC"), ("d", "srcA")]


class ReplayFuzz(unittest.TestCase):
    def test_random_stream_replays_and_audits_identically(self):
        rng = random.Random(20261125)
        for trial in range(12):
            tmp = tempfile.TemporaryDirectory()
            root = Path(tmp.name)
            try:
                rt = RelayRuntime.create(root, SEED, fsync=False)
                setup_link(rt, "L1", 1, AGENTS)
                seq = 0
                used_agents = set()
                for step in range(40):
                    roll = rng.random()
                    if roll < 0.55:
                        seq += 1
                        pair = rng.sample([a for a, _ in AGENTS], 2)
                        used_agents.update(pair)
                        ev = make_message(
                            rt,
                            msg_id=f"t{trial}-m{seq}",
                            link="L1",
                            gen=1,
                            seq=seq,
                            signers=pair,
                            segment=f"s{seq % 7}",
                        )
                        out = rt.submit(ev)
                        # All chosen pairs are independent unless they share srcA
                        # (a, d).  Accept either publish or the expected refusal.
                        self.assertIn(out.status, (S_ACCEPTED, "rejected"))
                    elif roll < 0.85:
                        candidates = [a for a, _ in AGENTS if a in used_agents]
                        if candidates:
                            agent = rng.choice(candidates)
                            out = rt.submit({"kind": "revoke_agent", "agent": agent})
                            self.assertIn(out.status, (S_ACCEPTED, "duplicate"))
                    else:
                        # Idempotent retry of the last accepted message, if any.
                        visible = rt.state.visible_messages()
                        if visible:
                            last = visible[-1]
                            if seq == last.seq:
                                pair = list(last.valid_agents)
                                ev = make_message(
                                    rt,
                                    msg_id=last.msg_id,
                                    link=last.link,
                                    gen=last.generation,
                                    seq=last.seq,
                                    signers=pair,
                                    segment=last.segment,
                                    payload=last.payload,
                                    request_key=last.request_key,
                                )
                                replay = rt.submit(ev)
                                self.assertIn(replay.status, ("duplicate", "rejected"))

                live_footprint = rt.state.footprint()
                live_digest = rt.state.visible_digest()
                rt.close()

                rt2 = RelayRuntime.open(root, fsync=False)
                try:
                    self.assertEqual(rt2.state.footprint(), live_footprint, f"trial {trial}")
                    self.assertEqual(rt2.state.visible_digest(), live_digest, f"trial {trial}")
                    report = audit_store(root)
                    self.assertTrue(report.chain_ok, f"trial {trial}")
                    self.assertEqual(report.divergences, [], f"trial {trial}")
                    self.assertEqual(compare_with_runtime(report, rt2), [], f"trial {trial}")
                finally:
                    rt2.close()
            finally:
                tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
