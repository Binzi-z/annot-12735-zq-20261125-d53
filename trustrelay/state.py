"""Transactional relay state machine over the checksum-chained journal.

Published messages become visible only after an accepted ``submit_message``
record is durably on disk.  Every decision, including rejections and idempotent
replays, is journaled with a stable reason code so the independent verifier can
reconstruct state and audit why a message is (not) visible.

Lease lifecycle
    open_lease      create a STAGED lease for (link, generation)
    register_agent  bind an agent + control source to a STAGED lease
    activate_lease  STAGED -> ACTIVE once two independent sources exist
    migrate         source ACTIVE -> INACTIVE, target STAGED -> ACTIVE
    revoke_agent    governs future publishing, never rewrites history

Publish rules
  * the message binds one link, lease generation, raw-content digest and a
    contiguous per-lease sequence number;
  * exactly two approvals, two distinct agents, for this link/generation;
  * the two agents have distinct control sources, so one source counts once;
  * both MACs cover link/generation/seq/segment/digest;
  * neither agent is revoked at publish time;
  * the lease is ACTIVE and the sequence is ``watermark + 1``.

Revocation is non-retroactive and local
  * messages stay visible and the published watermark never regresses;
  * only messages co-signed by the revoked agent are re-evaluated;
  * a message remains independently provable while at least one co-signer
    survives, so revoking one of two agents keeps the old provable watermark;
  * the per-lease provable watermark is the contiguous prefix that is still
    backed by surviving evidence.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .journal import Journal
from .model import (
    Approval,
    JournalIntegrityError,
    KINDS,
    MessageRecord,
    Outcome,
    R_AGENT_GENERATION_MISMATCH,
    R_AGENT_LINK_MISMATCH,
    R_AGENT_REGISTRATION_CONFLICT,
    R_APPROVAL_SHAPE,
    R_DIGEST_MISMATCH,
    R_DUPLICATE_AGENT,
    R_DUPLICATE_RECEIPT,
    R_IDEMPOTENCY_CONFLICT,
    R_IDEMPOTENT_REPLAY,
    R_INVALID_LEASE,
    R_INVALID_SIGNATURE,
    R_LEASE_ALREADY_ACTIVE,
    R_LEASE_ALREADY_OPEN,
    R_LEASE_NOT_ACTIVE,
    R_LEASE_NOT_READY,
    R_LEASE_UNKNOWN,
    R_MALFORMED,
    R_MESSAGE_ID_CONFLICT,
    R_MIGRATION_SOURCE_NOT_ACTIVE,
    R_MIGRATION_TARGET_UNKNOWN,
    R_RECEIPT_ID_CONFLICT,
    R_RECEIPT_MISMATCH,
    R_REGISTRATION_CLOSED,
    R_REVOKED_AGENT,
    R_SAME_CONTROL_SOURCE,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REGRESSION,
    R_UNKNOWN_AGENT,
    R_UNKNOWN_EVENT,
    R_UNKNOWN_MESSAGE,
    ReceiptRecord,
    ReplyLost,
    S_ACCEPTED,
    S_DUPLICATE,
    S_REJECTED,
    canonical_bytes,
    canonicalize_event,
    is_hex64,
    is_int,
    is_nonempty_str,
    payload_digest,
    request_fingerprint,
    sha256_hex,
    signature_statement,
    verify_approval,
)

STAGED = "staged"
ACTIVE = "active"
INACTIVE = "inactive"


@dataclass
class Lease:
    link: str
    generation: int
    status: str = STAGED
    agents: list[str] = field(default_factory=list)
    by_seq: dict[int, str] = field(default_factory=dict)
    watermark: int = 0
    provable_watermark: int = 0
    # Sequences known to be no longer independently provable.  Revocation is
    # monotone, so this set only grows.
    unprovable: set[int] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, int]:
        return (self.link, self.generation)

    def note_unprovable(self, seq: int) -> None:
        self.unprovable.add(seq)

    def recompute_provable_watermark(self) -> None:
        if not self.unprovable:
            self.provable_watermark = self.watermark
            return
        self.provable_watermark = min(self.unprovable) - 1


@dataclass(frozen=True)
class AgentState:
    agent: str
    control_source: str
    link: str
    generation: int
    revoked: bool = False


@dataclass(frozen=True)
class _Action:
    kind: str
    payload: dict[str, Any]


@dataclass
class RevocationStats:
    touched_messages: int = 0
    touched_partitions: int = 0
    touched_segments: int = 0


class RelayState:
    """Pure decision + apply core.  The journal wrapper is ``RelayRuntime``."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.leases: dict[tuple[str, int], Lease] = {}
        self.active: dict[str, int] = {}
        self.agents: dict[str, AgentState] = {}
        self.messages: dict[str, MessageRecord] = {}
        self.messages_by_lease: dict[tuple[str, int], dict[str, MessageRecord]] = {}
        self.segments: dict[tuple[str, int], dict[str, list[str]]] = {}
        self.agent_messages: dict[str, set[str]] = {}
        self.requests: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        self.receipts: dict[str, ReceiptRecord] = {}
        self.log_seq = 0
        self.last_revocation = RevocationStats()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def lease(self, link: str, generation: int) -> Lease | None:
        return self.leases.get((link, generation))

    def visible_messages(self, link: str | None = None) -> list[MessageRecord]:
        items = self.messages.values()
        if link is not None:
            items = [m for m in items if m.link == link]
        return sorted(items, key=lambda m: (m.link, m.generation, m.seq))

    def partition_fingerprint(self, link: str, generation: int) -> str:
        lease = self.leases.get((link, generation))
        if lease is None:
            return sha256_hex(b"missing-partition")
        items = []
        for seq in range(1, lease.watermark + 1):
            msg = self.messages[lease.by_seq[seq]]
            items.append(
                {
                    "seq": seq,
                    "msg_id": msg.msg_id,
                    "segment": msg.segment,
                    "digest": msg.digest,
                    "agents": list(msg.valid_agents),
                    "sources": list(msg.sources_at_publish),
                    "provable_sources": list(msg.provable_sources),
                }
            )
        return sha256_hex(
            canonical_bytes(
                {
                    "link": link,
                    "generation": generation,
                    "status": lease.status,
                    "watermark": lease.watermark,
                    "provable_watermark": lease.provable_watermark,
                    "agents": sorted(lease.agents),
                    "messages": items,
                }
            )
        )

    def footprint(self) -> dict[str, str]:
        return {
            f"{link}@{gen}": self.partition_fingerprint(link, gen)
            for (link, gen) in sorted(self.leases)
        }

    def visible_digest(self) -> str:
        return sha256_hex(
            canonical_bytes(
                [
                    {
                        "msg_id": m.msg_id,
                        "link": m.link,
                        "generation": m.generation,
                        "seq": m.seq,
                        "segment": m.segment,
                        "digest": m.digest,
                        "agents": list(m.valid_agents),
                        "sources": list(m.sources_at_publish),
                        "provable_sources": list(m.provable_sources),
                    }
                    for m in self.visible_messages()
                ]
            )
        )

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------
    def decide(self, event: Any, seq: int) -> tuple[Outcome, _Action | None]:
        if not isinstance(event, dict):
            return (Outcome(seq, "unknown", S_REJECTED, R_MALFORMED), None)
        kind = event.get("kind")
        if kind not in KINDS:
            label = kind if isinstance(kind, str) else "unknown"
            return (Outcome(seq, label, S_REJECTED, R_UNKNOWN_EVENT), None)
        return getattr(self, "_decide_" + kind)(event, seq)

    def _decide_open_lease(self, event: dict[str, Any], seq: int) -> tuple[Outcome, _Action | None]:
        link = event.get("link")
        generation = event.get("generation")
        if not is_nonempty_str(link) or not is_int(generation) or generation < 1:
            return (Outcome(seq, "open_lease", S_REJECTED, R_MALFORMED), None)
        if (link, generation) in self.leases:
            return (Outcome(seq, "open_lease", S_REJECTED, R_LEASE_ALREADY_OPEN), None)
        return (
            Outcome(seq, "open_lease", S_ACCEPTED),
            _Action("open_lease", {"link": link, "generation": generation}),
        )

    def _decide_register_agent(
        self, event: dict[str, Any], seq: int
    ) -> tuple[Outcome, _Action | None]:
        agent = event.get("agent")
        source = event.get("control_source")
        link = event.get("link")
        generation = event.get("generation")
        if (
            not is_nonempty_str(agent)
            or not is_nonempty_str(source)
            or not is_nonempty_str(link)
            or not is_int(generation)
            or generation < 1
        ):
            return (Outcome(seq, "register_agent", S_REJECTED, R_MALFORMED), None)
        lease = self.leases.get((link, generation))
        if lease is None:
            return (Outcome(seq, "register_agent", S_REJECTED, R_LEASE_UNKNOWN), None)
        existing = self.agents.get(agent)
        if existing is not None:
            if (
                existing.control_source == source
                and existing.link == link
                and existing.generation == generation
            ):
                return (
                    Outcome(seq, "register_agent", S_DUPLICATE, R_IDEMPOTENT_REPLAY),
                    None,
                )
            return (Outcome(seq, "register_agent", S_REJECTED, R_AGENT_REGISTRATION_CONFLICT), None)
        if lease.status != STAGED:
            return (Outcome(seq, "register_agent", S_REJECTED, R_REGISTRATION_CLOSED), None)
        return (
            Outcome(seq, "register_agent", S_ACCEPTED),
            _Action(
                "register_agent",
                {"agent": agent, "control_source": source, "link": link, "generation": generation},
            ),
        )

    def _decide_activate_lease(
        self, event: dict[str, Any], seq: int
    ) -> tuple[Outcome, _Action | None]:
        link = event.get("link")
        generation = event.get("generation")
        if not is_nonempty_str(link) or not is_int(generation) or generation < 1:
            return (Outcome(seq, "activate_lease", S_REJECTED, R_MALFORMED), None)
        lease = self.leases.get((link, generation))
        if lease is None:
            return (Outcome(seq, "activate_lease", S_REJECTED, R_LEASE_UNKNOWN), None)
        if lease.status == ACTIVE:
            return (Outcome(seq, "activate_lease", S_REJECTED, R_LEASE_ALREADY_ACTIVE), None)
        if link in self.active:
            return (Outcome(seq, "activate_lease", S_REJECTED, R_LEASE_ALREADY_ACTIVE), None)
        if lease.status != STAGED:
            return (Outcome(seq, "activate_lease", S_REJECTED, R_LEASE_NOT_ACTIVE), None)
        if not self._lease_ready(lease):
            return (Outcome(seq, "activate_lease", S_REJECTED, R_LEASE_NOT_READY), None)
        return (
            Outcome(seq, "activate_lease", S_ACCEPTED),
            _Action("activate_lease", {"link": link, "generation": generation}),
        )

    def _decide_migrate(self, event: dict[str, Any], seq: int) -> tuple[Outcome, _Action | None]:
        sl = event.get("source_link")
        fg = event.get("from_generation")
        tl = event.get("target_link")
        tg = event.get("to_generation")
        if (
            not is_nonempty_str(sl)
            or not is_nonempty_str(tl)
            or not is_int(fg)
            or not is_int(tg)
            or fg < 1
            or tg < 1
        ):
            return (Outcome(seq, "migrate", S_REJECTED, R_MALFORMED), None)
        if (sl, fg) == (tl, tg):
            return (Outcome(seq, "migrate", S_REJECTED, R_INVALID_LEASE), None)
        source = self.leases.get((sl, fg))
        if source is None:
            return (Outcome(seq, "migrate", S_REJECTED, R_LEASE_UNKNOWN), None)
        if source.status != ACTIVE:
            return (Outcome(seq, "migrate", S_REJECTED, R_MIGRATION_SOURCE_NOT_ACTIVE), None)
        target = self.leases.get((tl, tg))
        if target is None:
            return (Outcome(seq, "migrate", S_REJECTED, R_MIGRATION_TARGET_UNKNOWN), None)
        if target.status != STAGED:
            return (Outcome(seq, "migrate", S_REJECTED, R_LEASE_ALREADY_ACTIVE), None)
        if not self._lease_ready(target):
            return (Outcome(seq, "migrate", S_REJECTED, R_LEASE_NOT_READY), None)
        return (
            Outcome(seq, "migrate", S_ACCEPTED),
            _Action(
                "migrate",
                {"source_link": sl, "from_generation": fg, "target_link": tl, "to_generation": tg},
            ),
        )

    def _decide_revoke_agent(
        self, event: dict[str, Any], seq: int
    ) -> tuple[Outcome, _Action | None]:
        agent = event.get("agent")
        if not is_nonempty_str(agent):
            return (Outcome(seq, "revoke_agent", S_REJECTED, R_MALFORMED), None)
        existing = self.agents.get(agent)
        if existing is None:
            return (Outcome(seq, "revoke_agent", S_REJECTED, R_UNKNOWN_AGENT), None)
        if existing.revoked:
            # Same request replayed: keep the old effect and say so.
            return (Outcome(seq, "revoke_agent", S_DUPLICATE, R_IDEMPOTENT_REPLAY), None)
        return (
            Outcome(seq, "revoke_agent", S_ACCEPTED),
            _Action("revoke_agent", {"agent": agent}),
        )

    def _decide_submit_message(
        self, event: dict[str, Any], seq: int
    ) -> tuple[Outcome, _Action | None]:
        request_key = event.get("request_key")
        msg_id = event.get("msg_id")
        link = event.get("link")
        generation = event.get("generation")
        mseq = event.get("seq")
        segment = event.get("segment")
        digest = event.get("digest")
        approvals = event.get("approvals")
        if (
            not is_nonempty_str(request_key)
            or not is_nonempty_str(msg_id)
            or not is_nonempty_str(link)
            or not is_nonempty_str(segment)
            or not is_int(generation)
            or generation < 1
            or not is_int(mseq)
            or mseq < 1
            or not is_hex64(digest)
            or "payload" not in event
        ):
            return (Outcome(seq, "submit_message", S_REJECTED, R_MALFORMED, msg_id=_sid(msg_id)), None)
        if not isinstance(approvals, list) or len(approvals) != 2:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_APPROVAL_SHAPE, msg_id=msg_id),
                None,
            )
        pairs: list[Approval] = []
        for item in approvals:
            if (
                not isinstance(item, dict)
                or not is_nonempty_str(item.get("agent"))
                or not is_nonempty_str(item.get("sig"))
            ):
                return (
                    Outcome(seq, "submit_message", S_REJECTED, R_APPROVAL_SHAPE, msg_id=msg_id),
                    None,
                )
            pairs.append(Approval(item["agent"], item["sig"]))

        fingerprint = request_fingerprint(event)
        prior = self.requests.get(("submit_message", request_key))
        if prior is not None:
            prior_fp, prior_outcome = prior
            if prior_fp == fingerprint:
                return (
                    Outcome(
                        seq,
                        "submit_message",
                        S_DUPLICATE,
                        R_IDEMPOTENT_REPLAY,
                        msg_id=prior_outcome.get("msg_id") or msg_id,
                        request_key=request_key,
                        original_status=prior_outcome.get("status"),
                        original_reason=prior_outcome.get("reason"),
                    ),
                    None,
                )
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_IDEMPOTENCY_CONFLICT, msg_id=msg_id),
                None,
            )

        if msg_id in self.messages:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_MESSAGE_ID_CONFLICT, msg_id=msg_id),
                None,
            )
        try:
            expected_digest = payload_digest(event["payload"])
        except (TypeError, ValueError):
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_MALFORMED, msg_id=msg_id),
                None,
            )
        if digest != expected_digest:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_DIGEST_MISMATCH, msg_id=msg_id),
                None,
            )

        lease = self.leases.get((link, generation))
        if lease is None:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_LEASE_UNKNOWN, msg_id=msg_id),
                None,
            )
        if lease.status != ACTIVE:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_LEASE_NOT_ACTIVE, msg_id=msg_id),
                None,
            )

        if pairs[0].agent == pairs[1].agent:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_DUPLICATE_AGENT, msg_id=msg_id),
                None,
            )

        records: list[AgentState] = []
        for approval in pairs:
            agent_state = self.agents.get(approval.agent)
            if agent_state is None:
                return (
                    Outcome(seq, "submit_message", S_REJECTED, R_UNKNOWN_AGENT, msg_id=msg_id),
                    None,
                )
            if agent_state.link != link:
                return (
                    Outcome(seq, "submit_message", S_REJECTED, R_AGENT_LINK_MISMATCH, msg_id=msg_id),
                    None,
                )
            if agent_state.generation != generation:
                return (
                    Outcome(
                        seq, "submit_message", S_REJECTED, R_AGENT_GENERATION_MISMATCH, msg_id=msg_id
                    ),
                    None,
                )
            if agent_state.revoked:
                return (
                    Outcome(seq, "submit_message", S_REJECTED, R_REVOKED_AGENT, msg_id=msg_id),
                    None,
                )
            records.append(agent_state)

        statement = signature_statement(
            msg_id=msg_id,
            link=link,
            generation=generation,
            seq=mseq,
            segment=segment,
            digest=digest,
        )
        for approval in pairs:
            if not verify_approval(self.seed, approval.agent, statement, approval.sig):
                return (
                    Outcome(seq, "submit_message", S_REJECTED, R_INVALID_SIGNATURE, msg_id=msg_id),
                    None,
                )

        sources = {r.control_source for r in records}
        if len(sources) != 2:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_SAME_CONTROL_SOURCE, msg_id=msg_id),
                None,
            )

        if mseq <= lease.watermark:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_SEQUENCE_REGRESSION, msg_id=msg_id),
                None,
            )
        if mseq != lease.watermark + 1:
            return (
                Outcome(seq, "submit_message", S_REJECTED, R_SEQUENCE_GAP, msg_id=msg_id),
                None,
            )

        return (
            Outcome(seq, "submit_message", S_ACCEPTED, msg_id=msg_id, request_key=request_key),
            _Action(
                "submit_message",
                {
                    "event": event,
                    "fingerprint": fingerprint,
                    "approvals": pairs,
                    "agents": records,
                },
            ),
        )

    def _decide_submit_receipt(
        self, event: dict[str, Any], seq: int
    ) -> tuple[Outcome, _Action | None]:
        receipt_id = event.get("receipt_id")
        msg_id = event.get("msg_id")
        link = event.get("link")
        generation = event.get("generation")
        digest = event.get("digest")
        if (
            not is_nonempty_str(receipt_id)
            or not is_nonempty_str(msg_id)
            or not is_nonempty_str(link)
            or not is_int(generation)
            or generation < 1
            or not is_hex64(digest)
        ):
            return (Outcome(seq, "submit_receipt", S_REJECTED, R_MALFORMED), None)

        fingerprint = request_fingerprint(event)
        prior = self.requests.get(("submit_receipt", receipt_id))
        if prior is not None:
            prior_fp, prior_outcome = prior
            if prior_fp == fingerprint:
                return (
                    Outcome(
                        seq,
                        "submit_receipt",
                        S_DUPLICATE,
                        R_DUPLICATE_RECEIPT,
                        msg_id=prior_outcome.get("msg_id") or msg_id,
                        receipt_id=receipt_id,
                        late=prior_outcome.get("late"),
                        original_status=prior_outcome.get("status"),
                        original_reason=prior_outcome.get("reason"),
                    ),
                    None,
                )
            return (
                Outcome(
                    seq, "submit_receipt", S_REJECTED, R_RECEIPT_ID_CONFLICT, receipt_id=receipt_id
                ),
                None,
            )

        msg = self.messages.get(msg_id)
        if msg is None:
            return (
                Outcome(seq, "submit_receipt", S_REJECTED, R_UNKNOWN_MESSAGE, receipt_id=receipt_id),
                None,
            )
        if msg.link != link or msg.generation != generation or msg.digest != digest:
            return (
                Outcome(seq, "submit_receipt", S_REJECTED, R_RECEIPT_MISMATCH, receipt_id=receipt_id),
                None,
            )
        lease = self.leases[(msg.link, msg.generation)]
        late = lease.status != ACTIVE
        return (
            Outcome(seq, "submit_receipt", S_ACCEPTED, msg_id=msg_id, receipt_id=receipt_id, late=late),
            _Action(
                "submit_receipt",
                {
                    "receipt_id": receipt_id,
                    "msg_id": msg_id,
                    "link": link,
                    "generation": generation,
                    "digest": digest,
                    "late": late,
                    "fingerprint": fingerprint,
                },
            ),
        )

    # ------------------------------------------------------------------
    # Record / apply
    # ------------------------------------------------------------------
    def record(self, event: Any, outcome: Outcome, action: _Action | None) -> None:
        """Advance state for one journal record (called for every record)."""
        kind = outcome.kind
        # Idempotency protects *committed effects* only.  A rejected attempt is
        # re-decided on retry, so a message rejected for a sequence gap can be
        # resubmitted unchanged once the gap is filled.
        if kind == "submit_message" and isinstance(event, dict):
            request_key = event.get("request_key")
            slot = ("submit_message", request_key) if is_nonempty_str(request_key) else None
            if slot is not None and outcome.status == S_ACCEPTED and slot not in self.requests:
                self.requests[slot] = (request_fingerprint(event), outcome.as_dict())
        elif kind == "submit_receipt" and isinstance(event, dict):
            receipt_id = event.get("receipt_id")
            slot = ("submit_receipt", receipt_id) if is_nonempty_str(receipt_id) else None
            if slot is not None and outcome.status == S_ACCEPTED and slot not in self.requests:
                self.requests[slot] = (request_fingerprint(event), outcome.as_dict())
        if action is not None:
            self._apply(action, outcome)
        self.log_seq = outcome.log_seq

    def _apply(self, action: _Action, outcome: Outcome) -> None:
        kind = action.kind
        if kind == "open_lease":
            lease = Lease(action.payload["link"], action.payload["generation"])
            self.leases[lease.key] = lease
            self.messages_by_lease[lease.key] = {}
            self.segments[lease.key] = {}
        elif kind == "register_agent":
            p = action.payload
            self.agents[p["agent"]] = AgentState(
                p["agent"], p["control_source"], p["link"], p["generation"]
            )
            self.leases[(p["link"], p["generation"])].agents.append(p["agent"])
            self.agent_messages.setdefault(p["agent"], set())
        elif kind == "activate_lease":
            p = action.payload
            lease = self.leases[(p["link"], p["generation"])]
            lease.status = ACTIVE
            self.active[p["link"]] = p["generation"]
        elif kind == "migrate":
            p = action.payload
            source = self.leases[(p["source_link"], p["from_generation"])]
            target = self.leases[(p["target_link"], p["to_generation"])]
            source.status = INACTIVE
            target.status = ACTIVE
            self.active.pop(p["source_link"], None)
            self.active[p["target_link"]] = p["to_generation"]
        elif kind == "revoke_agent":
            self._revoke(action.payload["agent"])
        elif kind == "submit_message":
            self._apply_message(action.payload, outcome)
        elif kind == "submit_receipt":
            p = action.payload
            self.receipts[p["receipt_id"]] = ReceiptRecord(
                receipt_id=p["receipt_id"],
                msg_id=p["msg_id"],
                link=p["link"],
                generation=p["generation"],
                digest=p["digest"],
                late=p["late"],
                log_seq=outcome.log_seq,
            )
        else:  # pragma: no cover - defensive
            raise AssertionError(f"unknown action {kind}")

    def _apply_message(self, p: dict[str, Any], outcome: Outcome) -> None:
        event = p["event"]
        agents: list[AgentState] = p["agents"]
        message = MessageRecord(
            msg_id=event["msg_id"],
            request_key=event["request_key"],
            link=event["link"],
            generation=event["generation"],
            seq=event["seq"],
            segment=event["segment"],
            digest=event["digest"],
            payload=event["payload"],
            approvals=tuple(p["approvals"]),
            valid_agents=tuple(sorted(a.agent for a in agents)),
            sources_at_publish=tuple(sorted({a.control_source for a in agents})),
            log_seq=outcome.log_seq,
            provable_sources=tuple(sorted({a.control_source for a in agents})),
        )
        self.messages[message.msg_id] = message
        self.messages_by_lease[(message.link, message.generation)][message.msg_id] = message
        lease = self.leases[(message.link, message.generation)]
        lease.by_seq[message.seq] = message.msg_id
        lease.watermark = message.seq
        # A new link cannot jump the provable prefix past an earlier gap.
        lease.recompute_provable_watermark()
        for agent in message.valid_agents:
            self.agent_messages.setdefault(agent, set()).add(message.msg_id)
        self.segments[(message.link, message.generation)].setdefault(message.segment, []).append(
            message.msg_id
        )

    def _revoke(self, agent_id: str) -> None:
        old = self.agents[agent_id]
        self.agents[agent_id] = AgentState(
            old.agent, old.control_source, old.link, old.generation, revoked=True
        )
        touched = self.agent_messages.get(agent_id, set())
        partitions: set[tuple[str, int]] = set()
        segments: set[tuple[str, int, str]] = set()
        for msg_id in touched:
            msg = self.messages[msg_id]
            key = (msg.link, msg.generation)
            partitions.add(key)
            segments.add((msg.link, msg.generation, msg.segment))
            survivors = [a for a in msg.valid_agents if not self.agents[a].revoked]
            msg.provable_sources = tuple(
                sorted({self.agents[a].control_source for a in survivors})
            )
            if not msg.provable_sources:
                self.leases[key].note_unprovable(msg.seq)
        for key in partitions:
            self.leases[key].recompute_provable_watermark()
        self.last_revocation = RevocationStats(
            touched_messages=len(touched),
            touched_partitions=len(partitions),
            touched_segments=len(segments),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _lease_ready(self, lease: Lease) -> bool:
        sources = {
            self.agents[agent].control_source
            for agent in lease.agents
            if not self.agents[agent].revoked
        }
        return len(sources) >= 2


def _sid(value: Any) -> str | None:
    return value if isinstance(value, str) else None


class RelayRuntime:
    """Journal-backed runtime.  All mutations are serialized by one lock."""

    def __init__(self, journal: Journal, state: RelayState):
        self.journal = journal
        self.state = state
        self._lock = threading.RLock()

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, root: Path, seed: bytes, *, fsync: bool = True) -> "RelayRuntime":
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        journal = Journal.create(
            root / "relay.journal", root / "relay.meta.json", seed, fsync=fsync
        )
        return cls(journal, RelayState(seed))

    @classmethod
    def open(cls, root: Path, *, fsync: bool = True) -> "RelayRuntime":
        root = Path(root)
        journal = Journal.open_existing(
            root / "relay.journal", root / "relay.meta.json", fsync=fsync
        )
        state = RelayState(journal.seed)
        view = journal.scan()
        if not view.chain_ok:
            raise JournalIntegrityError(view.chain_error or "chain invalid")
        for record in view.records:
            event = canonicalize_event(record.event)
            outcome, action = state.decide(event, record.seq)
            if outcome.as_dict() != record.outcome:
                raise JournalIntegrityError(
                    f"replay diverged at seq {record.seq}: "
                    f"{outcome.as_dict()} != {record.outcome}"
                )
            state.record(event, outcome, action)
        return cls(journal, state)

    def close(self) -> None:
        with self._lock:
            self.journal.close()

    def __enter__(self) -> "RelayRuntime":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- operations --------------------------------------------------------
    def submit(
        self,
        event: dict[str, Any],
        *,
        after_commit: Callable[[Outcome], None] | None = None,
    ) -> Outcome:
        with self._lock:
            canonical = canonicalize_event(event)
            seq = self.journal.next_seq()
            outcome, action = self.state.decide(canonical, seq)
            self.journal.append(canonical, outcome.as_dict())
            self.state.record(canonical, outcome, action)
            if after_commit is not None:
                after_commit(outcome)
            return outcome

    def submit_with_lost_reply(self, event: dict[str, Any]) -> Outcome:
        """Commit durably, then simulate the reply path being severed."""

        def _lose(outcome: Outcome) -> None:
            raise ReplyLost(outcome)

        with self._lock:
            return self.submit(event, after_commit=_lose)

    # -- snapshots ---------------------------------------------------------
    def accounts(self) -> dict[str, dict[str, Any]]:
        return {
            agent: {
                "control_source": rec.control_source,
                "link": rec.link,
                "generation": rec.generation,
                "revoked": rec.revoked,
            }
            for agent, rec in sorted(self.agents.items())
        }

    def receipt_log(self) -> list[dict[str, Any]]:
        return [
            {"receipt_id": r.receipt_id, "msg_id": r.msg_id, "late": r.late, "log_seq": r.log_seq}
            for r in sorted(self.state.receipts.values(), key=lambda x: x.log_seq)
        ]


__all__ = [
    "RelayRuntime",
    "RelayState",
    "Lease",
    "AgentState",
    "RevocationStats",
    "ReplyLost",
    "ACTIVE",
    "STAGED",
    "INACTIVE",
]
