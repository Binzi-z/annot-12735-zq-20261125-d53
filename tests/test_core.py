"""Core semantics: binding, independence, watermarks, revocation, replay."""

from __future__ import annotations

import tempfile
import unittest

from tests.support import (
    SEED,
    activate,
    make_message,
    migrate,
    open_lease,
    register,
    revoke,
    setup_link,
    setup_two_links,
)
from trustrelay.events import receipt_event
from trustrelay.model import (
    R_APPROVAL_SHAPE,
    R_AGENT_GENERATION_MISMATCH,
    R_AGENT_LINK_MISMATCH,
    R_DIGEST_MISMATCH,
    R_DUPLICATE_AGENT,
    R_DUPLICATE_RECEIPT,
    R_IDEMPOTENCY_CONFLICT,
    R_IDEMPOTENT_REPLAY,
    R_INVALID_SIGNATURE,
    R_LEASE_NOT_ACTIVE,
    R_LEASE_NOT_READY,
    R_MESSAGE_ID_CONFLICT,
    R_MIGRATION_SOURCE_NOT_ACTIVE,
    R_REGISTRATION_CLOSED,
    R_REVOKED_AGENT,
    R_SAME_CONTROL_SOURCE,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REGRESSION,
    R_UNKNOWN_MESSAGE,
    S_ACCEPTED,
    S_DUPLICATE,
    S_REJECTED,
)
from trustrelay.state import RelayRuntime


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.rt = RelayRuntime.create(self.root, SEED, fsync=False)

    def tearDown(self):
        self.rt.close()
        self._tmp.cleanup()

    def submit(self, event):
        return self.rt.submit(event)


class LeaseLifecycleTests(Base):
    def test_activation_requires_two_independent_sources(self):
        open_lease(self.rt, "L1", 1)
        register(self.rt, "a1", "srcA", "L1", 1)
        out = activate(self.rt, "L1", 1)
        self.assertEqual(out.reason, R_LEASE_NOT_READY)
        register(self.rt, "b1", "srcA", "L1", 1)  # same source: still one
        self.assertEqual(activate(self.rt, "L1", 1).reason, R_LEASE_NOT_READY)
        register(self.rt, "b1b", "srcB", "L1", 1)
        self.assertEqual(activate(self.rt, "L1", 1).status, S_ACCEPTED)

    def test_registration_closes_after_activation(self):
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
        out = register(self.rt, "c1", "srcC", "L1", 1)
        self.assertEqual(out.reason, R_REGISTRATION_CLOSED)

    def test_publish_requires_active_lease(self):
        open_lease(self.rt, "L1", 1)
        register(self.rt, "a1", "srcA", "L1", 1)
        register(self.rt, "b1", "srcB", "L1", 1)
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.assertEqual(self.submit(ev).reason, R_LEASE_NOT_ACTIVE)
        self.assertEqual(self.rt.state.visible_messages(), [])


class BindingTests(Base):
    def setUp(self):
        super().setUp()
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])

    def test_digest_binding(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        ev["digest"] = "0" * 64
        self.assertEqual(self.submit(ev).reason, R_DIGEST_MISMATCH)

    def test_signature_covers_link_and_seq(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        ev["seq"] = 2  # signatures no longer match the statement
        self.assertEqual(self.submit(ev).reason, R_INVALID_SIGNATURE)

    def test_two_agent_link_mismatch(self):
        # Open a second active lease; the original L1 signers must not be able
        # to publish under L2 even though L2 exists and is active.
        setup_link(self.rt, "L2", 1, [("a2", "srcA2"), ("b2", "srcB2")])
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        ev["link"] = "L2"
        self.assertEqual(self.submit(ev).reason, R_AGENT_LINK_MISMATCH)

    def test_generation_mismatch(self):
        # Roll L1 from generation 1 to generation 2 (same link, new lease),
        # then sign with the old generation-1 agents but claim generation 2.
        open_lease(self.rt, "L1", 2)
        register(self.rt, "a1g2", "srcA", "L1", 2)
        register(self.rt, "b1g2", "srcB", "L1", 2)
        self.assertEqual(migrate(self.rt, "L1", 1, "L1", 2).status, S_ACCEPTED)
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        ev["generation"] = 2
        self.assertEqual(self.submit(ev).reason, R_AGENT_GENERATION_MISMATCH)

    def test_approval_shape(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        ev["approvals"] = ev["approvals"][:1]
        self.assertEqual(self.submit(ev).reason, R_APPROVAL_SHAPE)

    def test_duplicate_agent(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "a1"])
        self.assertEqual(self.submit(ev).reason, R_DUPLICATE_AGENT)


class IndependenceTests(Base):
    def test_same_control_source_counts_once(self):
        open_lease(self.rt, "L1", 1)
        register(self.rt, "a1", "shared", "L1", 1)
        register(self.rt, "b1", "shared", "L1", 1)
        # Two agents, one control source: not independently ready.
        self.assertEqual(activate(self.rt, "L1", 1).reason, R_LEASE_NOT_READY)
        # A third source makes the lease ready (two distinct sources).
        register(self.rt, "c1", "other", "L1", 1)
        self.assertEqual(activate(self.rt, "L1", 1).status, S_ACCEPTED)
        # But two same-source co-signers still cannot publish a message.
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.assertEqual(self.submit(ev).reason, R_SAME_CONTROL_SOURCE)
        self.assertEqual(self.rt.state.visible_messages(), [])
        # a1 + c1 are independent and publish.
        ok = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "c1"])
        self.assertEqual(self.submit(ok).status, S_ACCEPTED)

    def test_independent_pair_publishes(self):
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        out = self.submit(ev)
        self.assertEqual(out.status, S_ACCEPTED)
        msg = self.rt.state.visible_messages()[0]
        self.assertEqual(msg.sources_at_publish, ("srcA", "srcB"))
        self.assertEqual(msg.digest, ev["digest"])


class SequenceTests(Base):
    def setUp(self):
        super().setUp()
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])

    def test_gap_rejected_then_contiguous_accepts(self):
        ev2 = make_message(self.rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"])
        self.assertEqual(self.submit(ev2).reason, R_SEQUENCE_GAP)
        ev1 = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.assertEqual(self.submit(ev1).status, S_ACCEPTED)
        self.assertEqual(self.submit(ev2).status, S_ACCEPTED)

    def test_regression_rejected(self):
        ev1 = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.submit(ev1)
        again = make_message(self.rt, msg_id="m1b", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.assertEqual(self.submit(again).reason, R_SEQUENCE_REGRESSION)


class MigrationTests(Base):
    def test_migration_moves_only_active_link(self):
        setup_two_links(self.rt)
        old = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.submit(old)
        out = migrate(self.rt, "L1", 1, "L2", 1)
        self.assertEqual(out.status, S_ACCEPTED)
        # old link is frozen
        late = make_message(self.rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"])
        self.assertEqual(self.submit(late).reason, R_LEASE_NOT_ACTIVE)
        # new link publishes from its own agents
        new = make_message(self.rt, msg_id="m3", link="L2", gen=1, seq=1, signers=["a2", "b2"])
        self.assertEqual(self.submit(new).status, S_ACCEPTED)

    def test_second_migration_from_inactive_source_rejected(self):
        setup_two_links(self.rt)
        self.assertEqual(migrate(self.rt, "L1", 1, "L2", 1).status, S_ACCEPTED)
        open_lease(self.rt, "L3", 1)
        register(self.rt, "a3", "srcA3", "L3", 1)
        register(self.rt, "b3", "srcB3", "L3", 1)
        out = migrate(self.rt, "L1", 1, "L3", 1)
        self.assertEqual(out.reason, R_MIGRATION_SOURCE_NOT_ACTIVE)

    def test_target_not_ready(self):
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])
        open_lease(self.rt, "L2", 1)
        register(self.rt, "a2", "srcA2", "L2", 1)
        self.assertEqual(migrate(self.rt, "L1", 1, "L2", 1).reason, R_LEASE_NOT_READY)

    def test_receipt_late_after_migration(self):
        setup_two_links(self.rt)
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.submit(ev)
        receipt = receipt_event(
            receipt_id="rc1", msg_id="m1", link="L1", generation=1, digest=ev["digest"]
        )
        # receipt arrives while L1 is still active
        first = self.submit(receipt)
        self.assertEqual(first.status, S_ACCEPTED)
        self.assertFalse(first.late)
        migrate(self.rt, "L1", 1, "L2", 1)
        # duplicate receipt after migration: replay of the first, still not late
        dup = self.submit(dict(receipt))
        self.assertEqual(dup.status, S_DUPLICATE)
        self.assertEqual(dup.reason, R_DUPLICATE_RECEIPT)
        self.assertFalse(dup.late)
        # a fresh receipt for the same old message is now late
        receipt2 = receipt_event(
            receipt_id="rc2", msg_id="m1", link="L1", generation=1, digest=ev["digest"]
        )
        late = self.submit(receipt2)
        self.assertEqual(late.status, S_ACCEPTED)
        self.assertTrue(late.late)

    def test_receipt_for_unknown_message(self):
        setup_two_links(self.rt)
        receipt = receipt_event(
            receipt_id="rcX", msg_id="nope", link="L1", generation=1, digest="1" * 64
        )
        self.assertEqual(self.submit(receipt).reason, R_UNKNOWN_MESSAGE)


class RevocationTests(Base):
    def setUp(self):
        super().setUp()
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])

    def _publish(self, n):
        for seq in range(1, n + 1):
            ev = make_message(
                self.rt, msg_id=f"m{seq}", link="L1", gen=1, seq=seq, signers=["a1", "b1"]
            )
            self.assertEqual(self.submit(ev).status, S_ACCEPTED)

    def test_revoke_one_agent_keeps_old_watermark(self):
        self._publish(3)
        lease = self.rt.state.leases[("L1", 1)]
        self.assertEqual(lease.provable_watermark, 3)
        self.assertEqual(revoke(self.rt, "a1").status, S_ACCEPTED)
        self.assertEqual(lease.watermark, 3)
        self.assertEqual(lease.provable_watermark, 3)  # b1 alone still proves all
        self.assertEqual(len(self.rt.state.visible_messages()), 3)
        for msg in self.rt.state.visible_messages():
            self.assertEqual(msg.provable_sources, ("srcB",))

    def test_revoke_both_drops_provable_watermark_not_visibility(self):
        self._publish(3)
        revoke(self.rt, "a1")
        revoke(self.rt, "b1")
        lease = self.rt.state.leases[("L1", 1)]
        self.assertEqual(lease.watermark, 3)
        self.assertEqual(lease.provable_watermark, 0)
        self.assertEqual(len(self.rt.state.visible_messages()), 3)
        ev = make_message(self.rt, msg_id="m4", link="L1", gen=1, seq=4, signers=["a1", "b1"])
        self.assertEqual(self.submit(ev).reason, R_REVOKED_AGENT)

    def test_revoke_unknown_and_repeat(self):
        self.assertEqual(
            self.rt.submit({"kind": "revoke_agent", "agent": "zz"}).reason,
            "unknown_agent",
        )
        revoke(self.rt, "a1")
        repeat = revoke(self.rt, "a1")
        self.assertEqual(repeat.status, S_DUPLICATE)
        self.assertEqual(repeat.reason, R_IDEMPOTENT_REPLAY)

    def test_revoke_does_not_regress_published_watermark(self):
        self._publish(2)
        before = [(m.msg_id, m.digest) for m in self.rt.state.visible_messages()]
        revoke(self.rt, "a1")
        revoke(self.rt, "b1")
        after = [(m.msg_id, m.digest) for m in self.rt.state.visible_messages()]
        self.assertEqual(after, before)  # visibility and content are unchanged
        self.assertEqual(self.rt.state.leases[("L1", 1)].watermark, 2)


class IdempotencyTests(Base):
    def setUp(self):
        super().setUp()
        setup_link(self.rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")])

    def test_identical_retry_is_replay(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.assertEqual(self.submit(ev).status, S_ACCEPTED)
        replay = self.submit(dict(ev))
        self.assertEqual(replay.status, S_DUPLICATE)
        self.assertEqual(replay.reason, R_IDEMPOTENT_REPLAY)
        self.assertEqual(len(self.rt.state.visible_messages()), 1)

    def test_approval_reorder_is_same_request(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.submit(ev)
        reordered = dict(ev)
        reordered["approvals"] = list(reversed(ev["approvals"]))
        self.assertEqual(self.submit(reordered).status, S_DUPLICATE)

    def test_same_request_key_different_content_conflicts(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.submit(ev)
        changed = make_message(
            self.rt,
            msg_id="m1",
            link="L1",
            gen=1,
            seq=1,
            signers=["a1", "b1"],
            payload={"different": True},
            request_key=ev["request_key"],
        )
        self.assertEqual(self.submit(changed).reason, R_IDEMPOTENCY_CONFLICT)

    def test_message_id_conflict(self):
        ev = make_message(self.rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"])
        self.submit(ev)
        clash = make_message(
            self.rt,
            msg_id="m1",
            link="L1",
            gen=1,
            seq=2,
            signers=["a1", "b1"],
            request_key="other-key",
        )
        self.assertEqual(self.submit(clash).reason, R_MESSAGE_ID_CONFLICT)


if __name__ == "__main__":
    unittest.main()
