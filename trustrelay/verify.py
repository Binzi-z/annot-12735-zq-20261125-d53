"""Independent on-disk auditor.

Deliberately does **not** import ``RelayState``.  It re-parses the journal
bytes itself, re-verifies the checksum chain, re-derives every decision from
the recorded events using its own compact rule set, and then reports:

  * the visible messages it believes are durable;
  * the reason each non-visible submit was rejected;
  * the independent-provable waterline per lease;
  * every divergence between its own view and the recorded outcomes.

The point is to catch a runtime whose in-memory state drifted from what was
actually persisted (for example a committed write whose reply was lost).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import (
    GENESIS,
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
    S_ACCEPTED,
    S_DUPLICATE,
    S_REJECTED,
    canonicalize_event,
    is_hex64,
    is_int,
    is_nonempty_str,
    payload_digest,
    record_digest,
    request_fingerprint,
    sha256_hex,
    signature_statement,
    verify_approval,
)

STAGED = "staged"
ACTIVE = "active"
INACTIVE = "inactive"


@dataclass
class AuditLease:
    link: str
    generation: int
    status: str = STAGED
    agents: list[str] = field(default_factory=list)
    seqs: list[str] = field(default_factory=list)
    watermark: int = 0


@dataclass
class AuditMessage:
    msg_id: str
    link: str
    generation: int
    seq: int
    segment: str
    digest: str
    agents: tuple[str, ...]
    sources: tuple[str, ...]
    provable_sources: tuple[str, ...]
    log_seq: int


@dataclass
class AuditReport:
    chain_ok: bool
    chain_error: str | None
    records: int
    torn_tail_bytes: int
    head: str
    visible: list[AuditMessage]
    visible_digest: str
    rejections: list[dict[str, Any]]
    receipts: list[dict[str, Any]]
    leases: dict[str, dict[str, Any]]
    footprint: dict[str, str]
    divergences: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_ok": self.chain_ok,
            "chain_error": self.chain_error,
            "records": self.records,
            "torn_tail_bytes": self.torn_tail_bytes,
            "head": self.head,
            "visible_digest": self.visible_digest,
            "visible_count": len(self.visible),
            "rejection_count": len(self.rejections),
            "receipt_count": len(self.receipts),
            "divergences": list(self.divergences),
        }


class _Auditor:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.leases: dict[tuple[str, int], AuditLease] = {}
        self.active: dict[str, int] = {}
        self.agents: dict[str, dict[str, Any]] = {}
        self.messages: dict[str, AuditMessage] = {}
        self.requests: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.agent_messages: dict[str, list[str]] = {}
        self.segments: dict[tuple[str, int], dict[str, list[str]]] = {}

    # -- rule set, re-implemented independently ---------------------------
    def decide(self, event: Any, seq: int) -> dict[str, Any]:
        if not isinstance(event, dict):
            return _o(seq, "unknown", S_REJECTED, R_MALFORMED)
        kind = event.get("kind")
        if kind not in {
            "open_lease",
            "register_agent",
            "activate_lease",
            "migrate",
            "revoke_agent",
            "submit_message",
            "submit_receipt",
        }:
            return _o(seq, kind if isinstance(kind, str) else "unknown", S_REJECTED, R_UNKNOWN_EVENT)
        outcome = getattr(self, "_d_" + kind)(event, seq)
        # Idempotency protects committed effects only; rejected attempts are
        # re-decided when retried.
        if outcome["status"] == S_ACCEPTED:
            if kind == "submit_message" and is_nonempty_str(event.get("request_key")):
                slot = ("submit_message", event["request_key"])
                self.requests.setdefault(slot, (request_fingerprint(event), outcome))
            elif kind == "submit_receipt" and is_nonempty_str(event.get("receipt_id")):
                slot = ("submit_receipt", event["receipt_id"])
                self.requests.setdefault(slot, (request_fingerprint(event), outcome))
        return outcome
    def _d_open_lease(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        link, gen = e.get("link"), e.get("generation")
        if not is_nonempty_str(link) or not is_int(gen) or gen < 1:
            return _o(seq, "open_lease", S_REJECTED, R_MALFORMED)
        if (link, gen) in self.leases:
            return _o(seq, "open_lease", S_REJECTED, R_LEASE_ALREADY_OPEN)
        self.leases[(link, gen)] = AuditLease(link, gen)
        return _o(seq, "open_lease", S_ACCEPTED)

    def _d_register_agent(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        agent, src = e.get("agent"), e.get("control_source")
        link, gen = e.get("link"), e.get("generation")
        if (
            not is_nonempty_str(agent)
            or not is_nonempty_str(src)
            or not is_nonempty_str(link)
            or not is_int(gen)
            or gen < 1
        ):
            return _o(seq, "register_agent", S_REJECTED, R_MALFORMED)
        lease = self.leases.get((link, gen))
        if lease is None:
            return _o(seq, "register_agent", S_REJECTED, R_LEASE_UNKNOWN)
        old = self.agents.get(agent)
        if old is not None:
            if (old["source"], old["link"], old["generation"]) == (src, link, gen):
                return _o(seq, "register_agent", S_DUPLICATE, R_IDEMPOTENT_REPLAY)
            return _o(seq, "register_agent", S_REJECTED, R_AGENT_REGISTRATION_CONFLICT)
        if lease.status != STAGED:
            return _o(seq, "register_agent", S_REJECTED, R_REGISTRATION_CLOSED)
        self.agents[agent] = {
            "source": src,
            "link": link,
            "generation": gen,
            "revoked": False,
        }
        lease.agents.append(agent)
        self.agent_messages.setdefault(agent, [])
        return _o(seq, "register_agent", S_ACCEPTED)

    def _ready(self, lease: AuditLease) -> bool:
        return (
            len(
                {
                    self.agents[a]["source"]
                    for a in lease.agents
                    if not self.agents[a]["revoked"]
                }
            )
            >= 2
        )

    def _d_activate_lease(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        link, gen = e.get("link"), e.get("generation")
        if not is_nonempty_str(link) or not is_int(gen) or gen < 1:
            return _o(seq, "activate_lease", S_REJECTED, R_MALFORMED)
        lease = self.leases.get((link, gen))
        if lease is None:
            return _o(seq, "activate_lease", S_REJECTED, R_LEASE_UNKNOWN)
        if lease.status == ACTIVE or link in self.active:
            return _o(seq, "activate_lease", S_REJECTED, R_LEASE_ALREADY_ACTIVE)
        if lease.status != STAGED:
            return _o(seq, "activate_lease", S_REJECTED, R_LEASE_NOT_ACTIVE)
        if not self._ready(lease):
            return _o(seq, "activate_lease", S_REJECTED, R_LEASE_NOT_READY)
        lease.status = ACTIVE
        self.active[link] = gen
        return _o(seq, "activate_lease", S_ACCEPTED)

    def _d_migrate(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        sl, fg = e.get("source_link"), e.get("from_generation")
        tl, tg = e.get("target_link"), e.get("to_generation")
        if (
            not is_nonempty_str(sl)
            or not is_nonempty_str(tl)
            or not is_int(fg)
            or not is_int(tg)
            or fg < 1
            or tg < 1
        ):
            return _o(seq, "migrate", S_REJECTED, R_MALFORMED)
        if (sl, fg) == (tl, tg):
            return _o(seq, "migrate", S_REJECTED, R_INVALID_LEASE)
        src = self.leases.get((sl, fg))
        if src is None:
            return _o(seq, "migrate", S_REJECTED, R_LEASE_UNKNOWN)
        if src.status != ACTIVE:
            return _o(seq, "migrate", S_REJECTED, R_MIGRATION_SOURCE_NOT_ACTIVE)
        dst = self.leases.get((tl, tg))
        if dst is None:
            return _o(seq, "migrate", S_REJECTED, R_MIGRATION_TARGET_UNKNOWN)
        if dst.status != STAGED:
            return _o(seq, "migrate", S_REJECTED, R_LEASE_ALREADY_ACTIVE)
        if not self._ready(dst):
            return _o(seq, "migrate", S_REJECTED, R_LEASE_NOT_READY)
        src.status = INACTIVE
        dst.status = ACTIVE
        self.active.pop(sl, None)
        self.active[tl] = tg
        return _o(seq, "migrate", S_ACCEPTED)

    def _d_revoke_agent(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        agent = e.get("agent")
        if not is_nonempty_str(agent):
            return _o(seq, "revoke_agent", S_REJECTED, R_MALFORMED)
        rec = self.agents.get(agent)
        if rec is None:
            return _o(seq, "revoke_agent", S_REJECTED, R_UNKNOWN_AGENT)
        if rec["revoked"]:
            return _o(seq, "revoke_agent", S_DUPLICATE, R_IDEMPOTENT_REPLAY)
        rec["revoked"] = True
        for msg_id in self.agent_messages.get(agent, ()):
            msg = self.messages[msg_id]
            survivors = [a for a in msg.agents if not self.agents[a]["revoked"]]
            msg.provable_sources = tuple(
                sorted({self.agents[a]["source"] for a in survivors})
            )
        return _o(seq, "revoke_agent", S_ACCEPTED)

    def _d_submit_message(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        rk, mid = e.get("request_key"), e.get("msg_id")
        link, gen, mseq = e.get("link"), e.get("generation"), e.get("seq")
        seg, digest = e.get("segment"), e.get("digest")
        apps = e.get("approvals")
        if (
            not is_nonempty_str(rk)
            or not is_nonempty_str(mid)
            or not is_nonempty_str(link)
            or not is_nonempty_str(seg)
            or not is_int(gen)
            or gen < 1
            or not is_int(mseq)
            or mseq < 1
            or not is_hex64(digest)
            or "payload" not in e
        ):
            return _o(seq, "submit_message", S_REJECTED, R_MALFORMED, msg_id=_s(mid))
        if not isinstance(apps, list) or len(apps) != 2:
            return _o(seq, "submit_message", S_REJECTED, R_APPROVAL_SHAPE, msg_id=mid)
        ids: list[str] = []
        for item in apps:
            if (
                not isinstance(item, dict)
                or not is_nonempty_str(item.get("agent"))
                or not is_nonempty_str(item.get("sig"))
            ):
                return _o(seq, "submit_message", S_REJECTED, R_APPROVAL_SHAPE, msg_id=mid)
            ids.append(item["agent"])

        fp = request_fingerprint(e)
        prior = self.requests.get(("submit_message", rk))
        if prior is not None:
            prior_fp, prior_outcome = prior
            if prior_fp == fp:
                return _o(
                    seq,
                    "submit_message",
                    S_DUPLICATE,
                    R_IDEMPOTENT_REPLAY,
                    msg_id=prior_outcome.get("msg_id") or mid,
                    request_key=rk,
                    original_status=prior_outcome.get("status"),
                    original_reason=prior_outcome.get("reason"),
                )
            return _o(seq, "submit_message", S_REJECTED, R_IDEMPOTENCY_CONFLICT, msg_id=mid)
        if mid in self.messages:
            return _o(seq, "submit_message", S_REJECTED, R_MESSAGE_ID_CONFLICT, msg_id=mid)
        try:
            expected = payload_digest(e["payload"])
        except (TypeError, ValueError):
            return _o(seq, "submit_message", S_REJECTED, R_MALFORMED, msg_id=mid)
        if digest != expected:
            return _o(seq, "submit_message", S_REJECTED, R_DIGEST_MISMATCH, msg_id=mid)
        lease = self.leases.get((link, gen))
        if lease is None:
            return _o(seq, "submit_message", S_REJECTED, R_LEASE_UNKNOWN, msg_id=mid)
        if lease.status != ACTIVE:
            return _o(seq, "submit_message", S_REJECTED, R_LEASE_NOT_ACTIVE, msg_id=mid)
        if ids[0] == ids[1]:
            return _o(seq, "submit_message", S_REJECTED, R_DUPLICATE_AGENT, msg_id=mid)
        for agent in ids:
            rec = self.agents.get(agent)
            if rec is None:
                return _o(seq, "submit_message", S_REJECTED, R_UNKNOWN_AGENT, msg_id=mid)
            if rec["link"] != link:
                return _o(seq, "submit_message", S_REJECTED, R_AGENT_LINK_MISMATCH, msg_id=mid)
            if rec["generation"] != gen:
                return _o(
                    seq, "submit_message", S_REJECTED, R_AGENT_GENERATION_MISMATCH, msg_id=mid
                )
            if rec["revoked"]:
                return _o(seq, "submit_message", S_REJECTED, R_REVOKED_AGENT, msg_id=mid)
        stmt = signature_statement(
            msg_id=mid, link=link, generation=gen, seq=mseq, segment=seg, digest=digest
        )
        for item in apps:
            if not verify_approval(self.seed, item["agent"], stmt, item["sig"]):
                return _o(seq, "submit_message", S_REJECTED, R_INVALID_SIGNATURE, msg_id=mid)
        sources = {self.agents[a]["source"] for a in ids}
        if len(sources) != 2:
            return _o(seq, "submit_message", S_REJECTED, R_SAME_CONTROL_SOURCE, msg_id=mid)
        if mseq <= lease.watermark:
            return _o(seq, "submit_message", S_REJECTED, R_SEQUENCE_REGRESSION, msg_id=mid)
        if mseq != lease.watermark + 1:
            return _o(seq, "submit_message", S_REJECTED, R_SEQUENCE_GAP, msg_id=mid)

        msg = AuditMessage(
            msg_id=mid,
            link=link,
            generation=gen,
            seq=mseq,
            segment=seg,
            digest=digest,
            agents=tuple(sorted(ids)),
            sources=tuple(sorted(sources)),
            provable_sources=tuple(sorted(sources)),
            log_seq=seq,
        )
        self.messages[mid] = msg
        lease.seqs.append(mid)
        lease.watermark = mseq
        for agent in msg.agents:
            self.agent_messages.setdefault(agent, []).append(mid)
        self.segments.setdefault((link, gen), {}).setdefault(seg, []).append(mid)
        return _o(seq, "submit_message", S_ACCEPTED, msg_id=mid, request_key=rk)

    def _d_submit_receipt(self, e: dict[str, Any], seq: int) -> dict[str, Any]:
        rid, mid = e.get("receipt_id"), e.get("msg_id")
        link, gen, digest = e.get("link"), e.get("generation"), e.get("digest")
        if (
            not is_nonempty_str(rid)
            or not is_nonempty_str(mid)
            or not is_nonempty_str(link)
            or not is_int(gen)
            or gen < 1
            or not is_hex64(digest)
        ):
            return _o(seq, "submit_receipt", S_REJECTED, R_MALFORMED)
        fp = request_fingerprint(e)
        prior = self.requests.get(("submit_receipt", rid))
        if prior is not None:
            prior_fp, prior_outcome = prior
            if prior_fp == fp:
                return _o(
                    seq,
                    "submit_receipt",
                    S_DUPLICATE,
                    R_DUPLICATE_RECEIPT,
                    msg_id=prior_outcome.get("msg_id") or mid,
                    receipt_id=rid,
                    late=prior_outcome.get("late"),
                    original_status=prior_outcome.get("status"),
                    original_reason=prior_outcome.get("reason"),
                )
            return _o(seq, "submit_receipt", S_REJECTED, R_RECEIPT_ID_CONFLICT, receipt_id=rid)
        msg = self.messages.get(mid)
        if msg is None:
            return _o(seq, "submit_receipt", S_REJECTED, R_UNKNOWN_MESSAGE, receipt_id=rid)
        if (msg.link, msg.generation, msg.digest) != (link, gen, digest):
            return _o(seq, "submit_receipt", S_REJECTED, R_RECEIPT_MISMATCH, receipt_id=rid)
        late = self.leases[(link, gen)].status != ACTIVE
        self.receipts[rid] = {"msg_id": mid, "late": late, "log_seq": seq}
        return _o(seq, "submit_receipt", S_ACCEPTED, msg_id=mid, receipt_id=rid, late=late)

    # -- views ------------------------------------------------------------
    def provable_watermark(self, link: str, gen: int) -> int:
        lease = self.leases[(link, gen)]
        wm = 0
        for mseq, mid in enumerate(lease.seqs, start=1):
            if not self.messages[mid].provable_sources:
                break
            wm = mseq
        return wm

    def partition_fingerprint(self, link: str, gen: int) -> str:
        lease = self.leases[(link, gen)]
        items = []
        for mseq, mid in enumerate(lease.seqs, start=1):
            msg = self.messages[mid]
            items.append(
                {
                    "seq": mseq,
                    "msg_id": msg.msg_id,
                    "segment": msg.segment,
                    "digest": msg.digest,
                    "agents": list(msg.agents),
                    "sources": list(msg.sources),
                    "provable_sources": list(msg.provable_sources),
                }
            )
        return sha256_hex(
            _canon(
                {
                    "link": link,
                    "generation": gen,
                    "status": lease.status,
                    "watermark": lease.watermark,
                    "provable_watermark": self.provable_watermark(link, gen),
                    "agents": sorted(lease.agents),
                    "messages": items,
                }
            )
        )


def _o(
    seq: int,
    kind: str,
    status: str,
    reason: str | None = None,
    *,
    msg_id: str | None = None,
    request_key: str | None = None,
    receipt_id: str | None = None,
    late: bool | None = None,
    original_status: str | None = None,
    original_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "log_seq": seq,
        "kind": kind,
        "status": status,
        "reason": reason,
        "msg_id": msg_id,
        "request_key": request_key,
        "receipt_id": receipt_id,
        "late": late,
        "original_status": original_status,
        "original_reason": original_reason,
    }


def _s(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _canon(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def audit_store(root: Path) -> AuditReport:
    """Read the store from disk and independently re-derive everything."""
    root = Path(root)
    meta = json.loads((root / "relay.meta.json").read_bytes().decode("utf-8"))
    seed = bytes.fromhex(meta["seed_hex"])
    data = (root / "relay.journal").read_bytes()

    auditor = _Auditor(seed)
    divergences: list[str] = []
    rejections: list[dict[str, Any]] = []
    offset = 0
    expected = 1
    prev = GENESIS
    torn = 0
    chain_ok = True
    chain_error = None
    count = 0

    while offset < len(data):
        nl = data.find(b"\n", offset)
        if nl < 0:
            torn = len(data) - offset
            break
        line = data[offset:nl]
        try:
            rec = json.loads(line.decode("utf-8"))
            seq = rec["seq"]
            ok = (
                seq == expected
                and rec["prev"] == prev
                and rec["digest"] == record_digest(seq, prev, rec["event"], rec["outcome"])
            )
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            chain_ok, chain_error, torn = False, f"corrupt record at {offset}: {exc}", len(data) - offset
            break
        if not ok:
            chain_ok, chain_error, torn = False, f"chain mismatch at seq {seq}", len(data) - offset
            break
        event = canonicalize_event(rec["event"])
        derived = auditor.decide(event, seq)
        recorded = rec["outcome"]
        for key in (
            "log_seq",
            "kind",
            "status",
            "reason",
            "msg_id",
            "request_key",
            "receipt_id",
            "late",
            "original_status",
            "original_reason",
        ):
            if recorded.get(key) != derived.get(key):
                divergences.append(
                    f"seq {seq} field {key}: recorded={recorded.get(key)!r} derived={derived.get(key)!r}"
                )
        if recorded.get("status") == S_REJECTED:
            rejections.append(
                {
                    "log_seq": seq,
                    "kind": recorded.get("kind"),
                    "msg_id": recorded.get("msg_id"),
                    "reason": recorded.get("reason"),
                }
            )
        prev = rec["digest"]
        expected += 1
        offset = nl + 1
        count += 1

    visible = sorted(auditor.messages.values(), key=lambda m: (m.link, m.generation, m.seq))
    visible_digest = sha256_hex(
        _canon(
            [
                {
                    "msg_id": m.msg_id,
                    "link": m.link,
                    "generation": m.generation,
                    "seq": m.seq,
                    "segment": m.segment,
                    "digest": m.digest,
                    "agents": list(m.agents),
                    "sources": list(m.sources),
                    "provable_sources": list(m.provable_sources),
                }
                for m in visible
            ]
        )
    )
    leases = {
        f"{link}@{gen}": {
            "status": lease.status,
            "watermark": lease.watermark,
            "provable_watermark": auditor.provable_watermark(link, gen),
            "agents": sorted(lease.agents),
        }
        for (link, gen), lease in sorted(auditor.leases.items())
    }
    footprint = {
        f"{link}@{gen}": auditor.partition_fingerprint(link, gen)
        for (link, gen) in sorted(auditor.leases)
    }
    receipts = [
        {"receipt_id": rid, **rec}
        for rid, rec in sorted(auditor.receipts.items(), key=lambda kv: kv[1]["log_seq"])
    ]
    return AuditReport(
        chain_ok=chain_ok,
        chain_error=chain_error,
        records=count,
        torn_tail_bytes=torn,
        head=prev,
        visible=visible,
        visible_digest=visible_digest,
        rejections=rejections,
        receipts=receipts,
        leases=leases,
        footprint=footprint,
        divergences=divergences,
    )


def compare_with_runtime(report: AuditReport, runtime) -> list[str]:
    """Return divergences between the on-disk audit and a live runtime."""
    problems: list[str] = list(report.divergences)
    state = runtime.state
    if report.visible_digest != state.visible_digest():
        problems.append("visible-message digest differs between disk audit and runtime")
    live = state.footprint()
    for key, fp in report.footprint.items():
        if live.get(key) != fp:
            problems.append(f"partition {key} fingerprint differs between disk audit and runtime")
    for key in live:
        if key not in report.footprint:
            problems.append(f"partition {key} exists in runtime but not on disk")
    return problems
