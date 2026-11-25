"""Small-model exhaustion: every co-signer pair and every work interleaving.

A deliberately tiny model lets us enumerate the full space instead of
sampling:

* signer pairs over a 5-agent pool (ordered pairs, including duplicates),
  where two agents share a control source and one agent is revoked;
* tamper variants for every bound field;
* all interleavings of a 2-publish thread and a one-shot admin thread, plus
  revocation interleavings.

Each case runs in its own throw-away store so outcomes cannot leak.
"""

from __future__ import annotations

import itertools
import tempfile
import unittest
from pathlib import Path

from tests.support import SEED, make_message, migrate, open_lease, register, revoke, setup_link
from trustrelay.model import (
    R_AGENT_GENERATION_MISMATCH,
    R_AGENT_LINK_MISMATCH,
    R_DUPLICATE_AGENT,
    R_INVALID_SIGNATURE,
    R_REVOKED_AGENT,
    R_SAME_CONTROL_SOURCE,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REGRESSION,
    S_ACCEPTED,
    S_REJECTED,
)
from trustrelay.state import RelayRuntime

# agent -> control source.  a1/a2 share one source; d1 is revoked in the pool.
POOL = {
    "a1": "srcA",
    "a2": "srcA",
    "b1": "srcB",
    "c1": "srcC",
    "d1": "srcD",
}


def fresh_store():
    tmp = tempfile.TemporaryDirectory()
    rt = RelayRuntime.create(Path(tmp.name), SEED, fsync=False)
    return tmp, rt


def oracle_pair(rt, left, right, link, gen):
    """Independent statement of the publish rule for a co-signer pair."""
    if left == right:
        return R_DUPLICATE_AGENT
    for agent in (left, right):
        rec = rt.state.agents[agent]
        if rec.revoked:
            return R_REVOKED_AGENT
        if rec.link != link or rec.generation != gen:
            return R_AGENT_LINK_MISMATCH
    if POOL[left] == POOL[right]:
        return R_SAME_CONTROL_SOURCE
    return None


class SignerPairExhaustion(unittest.TestCase):
    def test_every_ordered_pair(self):
        tmp, rt = fresh_store()
        try:
            setup_link(rt, "L1", 1, list(POOL.items()))
            # Also register a longer-lived second lease so link mismatch is real.
            setup_link(rt, "L2", 1, [("x1", "sx"), ("y1", "sy")])
            revoke(rt, "d1")
            checked = 0
            for left, right in itertools.product(POOL, repeat=2):
                seq = 1
                already = any(m.seq == 1 for m in rt.state.visible_messages())
                ev = make_message(
                    rt,
                    msg_id=f"m-{left}-{right}",
                    link="L1",
                    gen=1,
                    seq=seq,
                    signers=[left, right],
                )
                out = rt.submit(ev)
                expected = oracle_pair(rt, left, right, "L1", 1)
                if expected is None:
                    if already:
                        # The eligible pair is valid in principle, but seq 1 is
                        # already taken, so it must be refused on the watermark.
                        self.assertEqual(out.status, S_REJECTED, (left, right, out))
                        self.assertEqual(out.reason, R_SEQUENCE_REGRESSION, (left, right, out))
                    else:
                        self.assertEqual(out.status, S_ACCEPTED, (left, right, out))
                else:
                    self.assertEqual(out.status, S_REJECTED, (left, right, out))
                    self.assertEqual(out.reason, expected, (left, right, out))
                checked += 1
            self.assertEqual(checked, len(POOL) ** 2)
        finally:
            rt.close()
            tmp.cleanup()

    def test_pool_produces_exactly_one_publish_per_sequence(self):
        tmp, rt = fresh_store()
        try:
            setup_link(rt, "L1", 1, list(POOL.items()))
            revoke(rt, "d1")
            accepted_pairs = []
            for left, right in itertools.product(POOL, repeat=2):
                seq = 1
                ev = make_message(
                    rt,
                    msg_id=f"m-{left}-{right}",
                    link="L1",
                    gen=1,
                    seq=seq,
                    signers=[left, right],
                )
                out = rt.submit(ev)
                if out.status == S_ACCEPTED:
                    accepted_pairs.append((left, right))
                    break
            self.assertEqual(len(accepted_pairs), 1)
            self.assertEqual(len(rt.state.visible_messages()), 1)
            msg = rt.state.visible_messages()[0]
            self.assertEqual(len(msg.sources_at_publish), 2)
            self.assertEqual(len(set(msg.sources_at_publish)), 2)
        finally:
            rt.close()
            tmp.cleanup()


class TamperExhaustion(unittest.TestCase):
    FIELDS = ("link", "generation", "seq", "segment", "digest", "msg_id")

    def test_each_bound_field_tamper(self):
        for field in self.FIELDS:
            tmp, rt = fresh_store()
            try:
                setup_link(rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
                setup_link(rt, "L2", 1, [("a2", "srcA2"), ("b2", "srcB2")])
                ev = make_message(
                    rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"]
                )
                if field == "link":
                    ev["link"] = "L2"
                    # Agents are bound to L1, so the binding check preempts the
                    # MAC check; either way the tampered request is refused.
                    allowed = {R_AGENT_LINK_MISMATCH, R_INVALID_SIGNATURE}
                elif field == "generation":
                    ev["generation"] = 2
                    allowed = {
                        R_AGENT_GENERATION_MISMATCH,
                        R_INVALID_SIGNATURE,
                        "lease_unknown",
                    }
                elif field == "seq":
                    ev["seq"] = 2
                    allowed = {R_INVALID_SIGNATURE}
                elif field == "segment":
                    ev["segment"] = "other-segment"
                    allowed = {R_INVALID_SIGNATURE}
                elif field == "digest":
                    ev["digest"] = "a" * 64
                    allowed = {"digest_mismatch"}
                else:  # msg_id
                    ev["msg_id"] = "m1-renamed"
                    allowed = {R_INVALID_SIGNATURE}
                out = rt.submit(ev)
                self.assertEqual(out.status, S_REJECTED, field)
                self.assertIn(out.reason, allowed, (field, out.reason))
                self.assertEqual(rt.state.visible_messages(), [], field)
            finally:
                rt.close()
                tmp.cleanup()

    def test_approval_order_permutation_is_stable(self):
        pairs = itertools.permutations([0, 1])
        outcomes = []
        for order in pairs:
            tmp, rt = fresh_store()
            try:
                setup_link(rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
                ev = make_message(
                    rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"]
                )
                ev["approvals"] = [ev["approvals"][i] for i in order]
                outcomes.append(rt.submit(ev).status)
                self.assertEqual([m.msg_id for m in rt.state.visible_messages()], ["m1"])
            finally:
                rt.close()
                tmp.cleanup()
        self.assertEqual(outcomes, [S_ACCEPTED, S_ACCEPTED])


class WorkInterleavingExhaustion(unittest.TestCase):
    """Enumerate all linear extensions of two program orders on real stores."""

    @staticmethod
    def _interleavings(a_ops, b_ops):
        """All merges preserving each program's internal order."""
        out = []

        def walk(i, j, acc):
            if i == len(a_ops) and j == len(b_ops):
                out.append(tuple(acc))
                return
            if i < len(a_ops):
                acc.append(("a", a_ops[i]))
                walk(i + 1, j, acc)
                acc.pop()
            if j < len(b_ops):
                acc.append(("b", b_ops[j]))
                walk(i, j + 1, acc)
                acc.pop()

        walk(0, 0, [])
        return out

    def _setup(self):
        tmp = tempfile.TemporaryDirectory()
        rt = RelayRuntime.create(Path(tmp.name), SEED, fsync=False)
        from tests.support import setup_two_links

        setup_two_links(rt)
        return tmp, rt

    def test_publish_publish_versus_migrate(self):
        a_ops = ["m1", "m2"]
        merges = self._interleavings(a_ops, ["migrate"])
        self.assertEqual(len(merges), 3)
        for ordering in merges:
            tmp, rt = self._setup()
            try:
                events = {
                    "m1": make_message(
                        rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"]
                    ),
                    "m2": make_message(
                        rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"]
                    ),
                }
                outcomes = []
                for _thread, op in ordering:
                    if op == "migrate":
                        outcomes.append(("migrate", migrate(rt, "L1", 1, "L2", 1)))
                    else:
                        outcomes.append((op, rt.submit(events[op])))
                accepted = [m.msg_id for m in rt.state.visible_messages("L1")]
                # Whatever the order, the visible L1 messages must be a prefix.
                self.assertIn(accepted, ([], ["m1"], ["m1", "m2"]), ordering)
                for name, out in outcomes:
                    if name == "m2" and out.status == S_ACCEPTED:
                        self.assertIn("m1", accepted, ordering)
                    if out.status == S_REJECTED and name in ("m1", "m2"):
                        self.assertIn(
                            out.reason,
                            (R_SEQUENCE_REGRESSION, R_SEQUENCE_GAP, "lease_not_active"),
                            ordering,
                        )
                self.assertFalse(rt.state.leases[("L1", 1)].status == "active" and
                                 any(n == "migrate" for n, _ in outcomes))
            finally:
                rt.close()
                tmp.cleanup()

    def test_publish_versus_revoke(self):
        merges = self._interleavings(["m1", "m2"], ["revoke"])
        self.assertEqual(len(merges), 3)
        for ordering in merges:
            tmp, rt = self._setup()
            try:
                events = {
                    "m1": make_message(
                        rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"]
                    ),
                    "m2": make_message(
                        rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"]
                    ),
                }
                revoked = False
                for _thread, op in ordering:
                    if op == "revoke":
                        self.assertEqual(revoke(rt, "a1").status, S_ACCEPTED)
                        revoked = True
                    else:
                        out = rt.submit(events[op])
                        if revoked:
                            self.assertEqual(out.reason, R_REVOKED_AGENT, ordering)
                # Revocation never removes already visible messages.
                visible = {m.msg_id for m in rt.state.visible_messages()}
                self.assertTrue(visible <= {"m1", "m2"})
                lease = rt.state.leases[("L1", 1)]
                self.assertEqual(lease.watermark, len(visible))
                if visible:
                    # b1 survives wherever a1 was a co-signer, so proof holds.
                    self.assertEqual(lease.provable_watermark, lease.watermark)
            finally:
                rt.close()
                tmp.cleanup()

    def test_migrate_versus_revoke_target(self):
        # Revoking one target agent before migration must block the migration.
        tmp, rt = self._setup()
        try:
            revoke(rt, "a2")
            # b2 alone cannot make L2 ready.
            out = migrate(rt, "L1", 1, "L2", 1)
            self.assertEqual(out.reason, "lease_not_ready")
            self.assertEqual(rt.state.leases[("L2", 1)].status, "staged")
        finally:
            rt.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
