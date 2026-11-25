"""60k segmented messages: full replay vs single-lease local revocation.

Builds a store with five independent link/lease partitions holding 60,000
segmented messages in total, then compares:

  * FULL  - rebuild every partition from the journal from scratch;
  * LOCAL - replay once, then apply one revocation and only re-derive the
            touched partition.

It reports the touched message/partition/segment counts for the local update,
proves every untouched partition fingerprint is identical to the full replay,
and confirms an independent on-disk audit agrees.  Numbers are written to
``artifacts/benchmark.json``.  Implemented as a unittest method so it runs
under the same harness; it is intentionally a single, self-contained test.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from tests.support import SEED, make_message, setup_link
from trustrelay.model import S_ACCEPTED
from trustrelay.rebuild import full_rebuild
from trustrelay.state import RelayRuntime
from trustrelay.verify import audit_store

TOTAL_MESSAGES = 60_000
SEGMENTS = 256
PARTITIONS = [
    ("L1", 1, 30_000),
    ("L2", 1, 12_000),
    ("L3", 1, 8_000),
    ("L4", 1, 6_000),
    ("L5", 1, 4_000),
]
assert sum(c for _l, _g, c in PARTITIONS) == TOTAL_MESSAGES
TARGET = "L3"
TARGET_AGENTS = (f"{TARGET}-a", f"{TARGET}-b")
TARGET_COUNT = next(c for (link, _g, c) in PARTITIONS if link == TARGET)


def agent_names(link):
    return (f"{link}-a", f"{link}-b")


def build_full_store(root: Path) -> float:
    started = time.perf_counter()
    rt = RelayRuntime.create(root, SEED, fsync=False)
    try:
        for link, gen, _count in PARTITIONS:
            a, b = agent_names(link)
            setup_link(rt, link, gen, [(a, f"src-{link}-A"), (b, f"src-{link}-B")])
        for link, gen, count in PARTITIONS:
            a, b = agent_names(link)
            for seq in range(1, count + 1):
                segment = f"seg-{seq % SEGMENTS:03d}"
                out = rt.submit(
                    make_message(
                        rt,
                        msg_id=f"{link}-m{seq}",
                        link=link,
                        gen=gen,
                        seq=seq,
                        signers=[a, b],
                        segment=segment,
                        payload={"link": link, "seq": seq, "segment": segment, "v": 1},
                    )
                )
                if out.status != S_ACCEPTED:  # pragma: no cover - build guard
                    raise AssertionError(f"build rejected {link}/{seq}: {out}")
    finally:
        rt.close()
    return time.perf_counter() - started


def timed_reopen(root: Path):
    started = time.perf_counter()
    rt = RelayRuntime.open(root, fsync=False)
    return rt, time.perf_counter() - started


class RevocationBenchmark(unittest.TestCase):
    def test_full_vs_local_revocation(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        try:
            build_seconds = build_full_store(root)

            # ---- FULL rebuild of every partition (no revocation yet).
            rt_full, full_seconds = timed_reopen(root)
            try:
                full_footprint = rt_full.state.footprint()
                full_visible = len(rt_full.state.visible_messages())
                self.assertEqual(full_visible, TOTAL_MESSAGES)
                # Sanity: every target message is co-signed by the agent we revoke.
                full_target_watermark = rt_full.state.leases[(TARGET, 1)].watermark
            finally:
                rt_full.close()

            # ---- LOCAL: replay once, apply one revocation, touch one lease.
            rt_local, local_replay_seconds = timed_reopen(root)
            try:
                self.assertEqual(rt_local.state.footprint(), full_footprint)
                revoke_started = time.perf_counter()
                out = rt_local.submit({"kind": "revoke_agent", "agent": TARGET_AGENTS[0]})
                revoke_seconds = time.perf_counter() - revoke_started
                self.assertEqual(out.status, S_ACCEPTED)
                stats = rt_local.state.last_revocation
                local_footprint = rt_local.state.footprint()
                local_watermark = rt_local.state.leases[(TARGET, 1)].provable_watermark
                local_visible_digest = rt_local.state.visible_digest()

                # ---- FULL baseline: recompute every message in every lease.
                rebuild_started = time.perf_counter()
                rebuild_stats = full_rebuild(rt_local.state)
                full_rebuild_seconds = time.perf_counter() - rebuild_started
                # The naive rebuild must land on the identical state.
                self.assertEqual(rt_local.state.footprint(), local_footprint)
                self.assertEqual(
                    rt_local.state.leases[(TARGET, 1)].provable_watermark, local_watermark
                )
            finally:
                rt_local.close()

            # Local update touched exactly the target partition.
            self.assertEqual(stats.touched_partitions, 1)
            self.assertEqual(stats.touched_messages, TARGET_COUNT)
            # Revoking one of two co-signers preserves the independently
            # provable old waterline (the survivor proves every message).
            self.assertEqual(local_watermark, full_target_watermark)

            # Unrelated partitions are byte-identical to the full rebuild.
            untouched = {k: v for k, v in local_footprint.items() if not k.startswith(TARGET + "@")}
            full_untouched = {
                k: v for k, v in full_footprint.items() if not k.startswith(TARGET + "@")
            }
            self.assertEqual(untouched, full_untouched)
            self.assertNotEqual(local_footprint[f"{TARGET}@1"], full_footprint[f"{TARGET}@1"])

            # ---- FULL replay *including* the revocation must equal LOCAL.
            rt_after, full_after_seconds = timed_reopen(root)
            try:
                self.assertEqual(rt_after.state.footprint(), local_footprint)
                self.assertEqual(rt_after.receipt_log(), [])
            finally:
                rt_after.close()

            # ---- Independent on-disk audit agrees with the runtime.
            audit = audit_store(root)
            self.assertTrue(audit.chain_ok)
            self.assertEqual(audit.divergences, [])
            self.assertEqual(audit.visible_digest, local_visible_digest)
            self.assertEqual(len(audit.visible), TOTAL_MESSAGES)
            self.assertEqual(
                stats.touched_messages, sum(1 for m in audit.visible if m.link == TARGET)
            )
            self.assertEqual(
                audit.leases[f"{TARGET}@1"]["provable_watermark"], full_target_watermark
            )

            report = {
                "total_messages": TOTAL_MESSAGES,
                "partitions": [
                    {"link": link, "generation": gen, "messages": count}
                    for (link, gen, count) in PARTITIONS
                ],
                "segments_per_partition": SEGMENTS,
                "build_seconds": round(build_seconds, 3),
                "full_replay_seconds": round(full_seconds, 3),
                "local_replay_seconds": round(local_replay_seconds, 3),
                # Work to reach the post-revocation *proof state*, two ways.
                # Both start from an already-open runtime (journal replay is
                # shared and reported separately above).
                "full_rebuild_seconds": round(full_rebuild_seconds, 6),
                "local_revoke_seconds": round(revoke_seconds, 6),
                "local_vs_full_update_speedup": round(
                    full_rebuild_seconds / revoke_seconds, 1
                ),
                "touched": {
                    "messages": stats.touched_messages,
                    "partitions": stats.touched_partitions,
                    "segments": stats.touched_segments,
                    "messages_untouched": TOTAL_MESSAGES - stats.touched_messages,
                },
                "full_rebuild_touched": {
                    "messages": rebuild_stats.messages,
                    "partitions": rebuild_stats.partitions,
                    "segments": rebuild_stats.segments,
                },
                "touch_ratio_messages": round(stats.touched_messages / TOTAL_MESSAGES, 6),
                "unrelated_partitions_unchanged": untouched == full_untouched,
                "target_partition": f"{TARGET}@1",
                "target_watermark": full_target_watermark,
                "provable_watermark_preserved": local_watermark == full_target_watermark,
                "audit_divergences": len(audit.divergences),
            }
            artifacts = Path(__file__).resolve().parent.parent / "artifacts"
            artifacts.mkdir(exist_ok=True)
            (artifacts / "benchmark.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )

            # The local update must be a strict minority of the corpus.
            self.assertLess(stats.touched_messages, TOTAL_MESSAGES)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
