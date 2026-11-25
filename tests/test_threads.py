"""Two real threads, controllable barriers: migration races, late receipts,
commit-then-reply-loss, restart auditing, torn-tail recovery, publish races.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from tests.support import (
    SEED,
    make_message,
    migrate,
    register,
    revoke,
    setup_link,
    setup_two_links,
)
from trustrelay.events import receipt_event
from trustrelay.model import (
    R_APPROVAL_SHAPE,
    R_DIGEST_MISMATCH,
    R_SEQUENCE_GAP,
    S_ACCEPTED,
    S_DUPLICATE,
    S_REJECTED,
    ReplyLost,
)
from trustrelay.state import RelayRuntime
from trustrelay.verify import audit_store, compare_with_runtime


def run_ordered(first_fn, second_fn):
    """Run two real threads; ``first_fn`` completes before ``second_fn`` starts.

    A barrier makes both threads ready together; a second barrier releases the
    second thread only after the first has finished.  This gives a controlled,
    deterministic interleaving while both pieces of work still run on real
    threads.
    """
    start = threading.Barrier(2)
    first_done = threading.Barrier(2)
    results: dict[str, object] = {}
    errors: dict[str, BaseException] = {}

    def first():
        start.wait()
        try:
            results["first"] = first_fn()
        except BaseException as exc:  # noqa: BLE001 - surfaced to the test
            errors["first"] = exc
        finally:
            first_done.wait()

    def second():
        start.wait()
        first_done.wait()
        try:
            results["second"] = second_fn()
        except BaseException as exc:  # noqa: BLE001
            errors["second"] = exc

    t1 = threading.Thread(target=first, name="first")
    t2 = threading.Thread(target=second, name="second")
    t1.start()
    t2.start()
    t1.join(30)
    t2.join(30)
    if t1.is_alive() or t2.is_alive():
        raise AssertionError("worker thread did not finish (deadlock?)")
    return results, errors


def run_simultaneous(fn_a, fn_b):
    """Both threads pass one barrier, then race into the runtime."""
    start = threading.Barrier(2)
    results: dict[str, object] = {}
    errors: dict[str, BaseException] = {}

    def wrap(name, fn):
        start.wait()
        try:
            results[name] = fn()
        except BaseException as exc:  # noqa: BLE001
            errors[name] = exc

    t1 = threading.Thread(target=wrap, args=("a", fn_a), name="race-a")
    t2 = threading.Thread(target=wrap, args=("b", fn_b), name="race-b")
    t1.start()
    t2.start()
    t1.join(30)
    t2.join(30)
    if t1.is_alive() or t2.is_alive():
        raise AssertionError("worker thread did not finish (deadlock?)")
    return results, errors


class ThreadScenarioBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.rt = RelayRuntime.create(self.root, SEED, fsync=False)

    def tearDown(self):
        try:
            self.rt.close()
        finally:
            self._tmp.cleanup()

    def publish_m1(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        out = self.rt.submit(ev)
        self.assertEqual(out.status, S_ACCEPTED)
        return ev

    def receipt(self, rid, ev, link="L1", gen=1):
        return receipt_event(
            receipt_id=rid, msg_id=ev["msg_id"], link=link, generation=gen, digest=ev["digest"]
        )


class MigrationReceiptRaceTests(ThreadScenarioBase):
    def setUp(self):
        super().setUp()
        setup_two_links(self.rt)
        self.ev = self.publish_m1()

    def test_receipt_wins_before_migration(self):
        receipt = self.receipt("rc1", self.ev)
        results, errors = run_ordered(
            lambda: self.rt.submit(receipt),
            lambda: migrate(self.rt, "L1", 1, "L2", 1),
        )
        self.assertEqual(errors, {})
        self.assertEqual(results["first"].status, S_ACCEPTED)
        self.assertFalse(results["first"].late)
        self.assertEqual(results["second"].status, S_ACCEPTED)
        # A fresh receipt after migration is late, but does not hide the message.
        late = self.rt.submit(self.receipt("rc2", self.ev))
        self.assertTrue(late.late)
        self.assertEqual(len(self.rt.state.visible_messages("L1")), 1)

    def test_migration_wins_so_receipt_is_late(self):
        receipt = self.receipt("rc1", self.ev)
        results, errors = run_ordered(
            lambda: migrate(self.rt, "L1", 1, "L2", 1),
            lambda: self.rt.submit(receipt),
        )
        self.assertEqual(errors, {})
        self.assertEqual(results["first"].status, S_ACCEPTED)
        self.assertEqual(results["second"].status, S_ACCEPTED)
        self.assertTrue(results["second"].late)
        # The late receipt is visible in the receipt log with its late flag.
        log = self.rt.receipt_log()
        self.assertEqual(log[0]["receipt_id"], "rc1")
        self.assertTrue(log[0]["late"])
    def test_receipt_for_new_link_is_not_late(self):
        migrate(self.rt, "L1", 1, "L2", 1)
        ev = make_message(self.rt, msg_id="m2", link="L2", gen=1, seq=1, signers=["a2", "b2"])
        self.assertEqual(self.rt.submit(ev).status, S_ACCEPTED)
        receipt = receipt_event(
            receipt_id="rc-new", msg_id="m2", link="L2", generation=1, digest=ev["digest"]
        )
        out = self.rt.submit(receipt)
        self.assertFalse(out.late)


class CommitReplyLossTests(ThreadScenarioBase):
    def test_commit_then_reply_lost_then_retry_deduplicates(self):
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
        setup_link(self.rt, "L2", 1, [("a2", "srcA2"), ("b2", "srcB2")])
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        other = make_message(self.rt, msg_id="m2", link="L2", gen=1, seq=1, signers=["a2", "b2"])

        lost: list = []

        def commit_with_lost_reply():
            try:
                self.rt.submit_with_lost_reply(ev)
            except ReplyLost as exc:
                lost.append(exc.outcome)
                return "reply-lost"
            return "reply-delivered"

        # Two real threads race: one commits a message and loses its reply, the
        # other concurrently commits an independent message on another link.
        results, errors = run_simultaneous(
            commit_with_lost_reply,
            lambda: self.rt.submit(other),
        )
        self.assertEqual(errors, {})
        self.assertEqual(results["a"], "reply-lost")
        self.assertEqual(results["b"].status, S_ACCEPTED)
        self.assertEqual(len(lost), 1)
        self.assertEqual(lost[0].status, S_ACCEPTED)

        # Both commits are durable even though one caller never saw a reply.
        report = audit_store(self.root)
        self.assertEqual(report.visible_digest, self.rt.state.visible_digest())
        self.assertEqual(sorted(m.msg_id for m in report.visible), ["m1", "m2"])
        self.assertEqual(report.divergences, [])

        # A retry after the lost reply must be an idempotent replay.
        retry = self.rt.submit(dict(ev))
        self.assertEqual(retry.status, S_DUPLICATE)
        self.assertEqual(len(self.rt.state.visible_messages()), 2)

        # Restart and independently re-check: both messages survive, no dupes.
        self.rt.close()
        self.rt = RelayRuntime.open(self.root, fsync=False)
        self.assertEqual(sorted(m.msg_id for m in self.rt.state.visible_messages()), ["m1", "m2"])
        self.assertEqual(compare_with_runtime(audit_store(self.root), self.rt), [])

    def test_rejections_survive_restart_with_reasons(self):
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
        good = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])

        bad_digest = make_message(
            self.rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"]
        )
        bad_digest["digest"] = "f" * 64
        gap = make_message(self.rt, msg_id="m3", link="L1", gen=1, seq=3, signers=["a1", "b1"])

        self.assertEqual(self.rt.submit(good).status, S_ACCEPTED)
        self.assertEqual(self.rt.submit(bad_digest).reason, R_DIGEST_MISMATCH)
        self.assertEqual(self.rt.submit(gap).reason, R_SEQUENCE_GAP)

        self.rt.close()
        self.rt = RelayRuntime.open(self.root, fsync=False)

        self.assertEqual([m.msg_id for m in self.rt.state.visible_messages()], ["m1"])
        report = audit_store(self.root)
        reasons = {(r["msg_id"], r["reason"]) for r in report.rejections}
        self.assertIn(("m2", R_DIGEST_MISMATCH), reasons)
        self.assertIn(("m3", R_SEQUENCE_GAP), reasons)
        self.assertEqual(compare_with_runtime(report, self.rt), [])


class RestartAuditTests(ThreadScenarioBase):
    def test_restart_independent_recheck_matches(self):
        setup_two_links(self.rt)
        ev1 = self.publish_m1()
        self.rt.submit(self.receipt("rc1", ev1))
        # Same-source co-signers must be rejected and that reason persisted.
        setups = setup_link(self.rt, "L3", 1, [("a3", "same"), ("b3", "same"), ("c3", "other")])
        same_src = make_message(self.rt, msg_id="m3", link="L3", gen=1, seq=1, signers=["a3", "b3"])
        self.assertEqual(self.rt.submit(same_src).reason, "same_control_source")
        migrate(self.rt, "L1", 1, "L2", 1)
        # A receipt for the old link after migration is late.
        late = self.rt.submit(self.receipt("rc2", ev1))
        self.assertTrue(late.late)
        revoke(self.rt, "a1")

        live_digest = self.rt.state.visible_digest()
        live_footprint = self.rt.state.footprint()
        self.rt.close()

        # Reopen in a *fresh* runtime object and independently audit from bytes.
        self.rt = RelayRuntime.open(self.root, fsync=False)
        self.assertEqual(self.rt.state.visible_digest(), live_digest)
        self.assertEqual(self.rt.state.footprint(), live_footprint)
        report = audit_store(self.root)
        self.assertTrue(report.chain_ok)
        self.assertEqual(report.divergences, [])
        self.assertEqual(compare_with_runtime(report, self.rt), [])
        reasons = {r["reason"] for r in report.rejections}
        self.assertIn("same_control_source", reasons)

    def test_torn_tail_is_truncated_and_head_preserved(self):
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.rt.submit(ev)
        head_before = self.rt.journal.head()
        self.rt.close()

        journal_path = self.root / "relay.journal"
        with open(journal_path, "ab") as handle:
            handle.write(b'{"seq": 99, "prev": "deadbeef", "event": {')  # torn write
        torn_size = journal_path.stat().st_size

        self.rt = RelayRuntime.open(self.root, fsync=False)
        self.assertEqual(self.rt.journal.head(), head_before)
        self.assertLess(journal_path.stat().st_size, torn_size)
        self.assertEqual([m.msg_id for m in self.rt.state.visible_messages()], ["m1"])
        report = audit_store(self.root)
        self.assertTrue(report.chain_ok)
        self.assertEqual(report.divergences, [])


class ConcurrentPublishTests(ThreadScenarioBase):
    def setUp(self):
        super().setUp()
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])

    def test_two_threads_racing_same_sequence_accept_exactly_one(self):
        left = make_message(self.rt, msg_id="mL", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        right = make_message(self.rt, msg_id="mR", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        results, errors = run_simultaneous(
            lambda: self.rt.submit(left),
            lambda: self.rt.submit(right),
        )
        self.assertEqual(errors, {})
        statuses = sorted(o.status for o in results.values())
        self.assertEqual(statuses, [S_ACCEPTED, S_REJECTED])
        loser = next(o for o in results.values() if o.status == S_REJECTED)
        self.assertEqual(loser.reason, "sequence_regression")
        self.assertEqual(len(self.rt.state.visible_messages()), 1)
        report = audit_store(self.root)
        self.assertEqual(compare_with_runtime(report, self.rt), [])

    def test_out_of_order_thread_then_retry(self):
        ev1 = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        ev2 = make_message(self.rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"])
        results, errors = run_ordered(
            lambda: self.rt.submit(ev2),
            lambda: self.rt.submit(ev1),
        )
        self.assertEqual(errors, {})
        self.assertEqual(results["first"].reason, R_SEQUENCE_GAP)
        self.assertEqual(results["second"].status, S_ACCEPTED)
        # The rejected seq-2 attempt is re-decidable, not cached as final.
        retry = self.rt.submit(dict(ev2))
        self.assertEqual(retry.status, S_ACCEPTED)
        self.assertEqual([m.seq for m in self.rt.state.visible_messages()], [1, 2])


if __name__ == "__main__":
    unittest.main()
