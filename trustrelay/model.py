"""Core value objects and deterministic encodings for the offline trust relay.

The relay is deliberately network-free: the checksum-chained append-only
journal is the only synthetic queue.  All identifiers, signatures and decisions
are deterministic so that a second implementation (the independent verifier)
can re-derive state after a restart and compare outcomes.

This is a synthetic HMAC approval model, not a production signature scheme.
The master seed lives in the store metadata so the verifier can re-check
historical approvals.  Keys never leave the throw-away test directory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

SIGNATURE_VERSION = 1
SIGNATURE_PURPOSE = "trustrelay/countersign/v1"
GENESIS = "0" * 64
HEX_DIGITS = frozenset("0123456789abcdef")

# ---------------------------------------------------------------------------
# Stable reason codes.  Runtime and independent verifier both emit these
# strings; tests assert exact equality after a restart.
# ---------------------------------------------------------------------------
R_MALFORMED = "malformed_request"
R_UNKNOWN_EVENT = "unknown_event"
R_INVALID_LEASE = "invalid_lease"
R_INVALID_SEQUENCE = "invalid_sequence"
R_LEASE_UNKNOWN = "lease_unknown"
R_LEASE_NOT_ACTIVE = "lease_not_active"
R_LEASE_ALREADY_OPEN = "lease_already_open"
R_LEASE_ALREADY_ACTIVE = "lease_already_active"
R_LEASE_NOT_READY = "lease_not_ready"
R_REGISTRATION_CLOSED = "registration_closed"
R_AGENT_REGISTRATION_CONFLICT = "agent_registration_conflict"
R_UNKNOWN_AGENT = "unknown_agent"
R_MIGRATION_SOURCE_NOT_ACTIVE = "migration_source_not_active"
R_MIGRATION_TARGET_UNKNOWN = "migration_target_unknown"
R_IDEMPOTENT_REPLAY = "idempotent_replay"
R_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
R_MESSAGE_ID_CONFLICT = "message_id_conflict"
R_DIGEST_MISMATCH = "digest_mismatch"
R_SEQUENCE_REGRESSION = "sequence_regression"
R_SEQUENCE_GAP = "sequence_gap"
R_APPROVAL_SHAPE = "approval_shape"
R_DUPLICATE_AGENT = "duplicate_agent"
R_AGENT_LINK_MISMATCH = "agent_link_mismatch"
R_AGENT_GENERATION_MISMATCH = "agent_generation_mismatch"
R_REVOKED_AGENT = "revoked_agent"
R_INVALID_SIGNATURE = "invalid_signature"
R_SAME_CONTROL_SOURCE = "same_control_source"
R_DUPLICATE_RECEIPT = "duplicate_receipt"
R_RECEIPT_ID_CONFLICT = "receipt_id_conflict"
R_UNKNOWN_MESSAGE = "unknown_message"
R_RECEIPT_MISMATCH = "receipt_mismatch"

KINDS = frozenset(
    {
        "open_lease",
        "register_agent",
        "activate_lease",
        "migrate",
        "revoke_agent",
        "submit_message",
        "submit_receipt",
    }
)

S_ACCEPTED = "accepted"
S_REJECTED = "rejected"
S_DUPLICATE = "duplicate"


# ---------------------------------------------------------------------------
# Deterministic encodings
# ---------------------------------------------------------------------------
def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON encoding used for hashes, digests and MAC statements."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_digest(payload: Any) -> str:
    """Raw-content digest bound by every published message."""
    return sha256_hex(canonical_bytes(payload))


def derive_agent_key(seed: bytes, agent_id: str) -> bytes:
    """Derive a deterministic, test-only MAC key for one agent."""
    return hmac.new(seed, b"agent-key:" + agent_id.encode("utf-8"), hashlib.sha256).digest()


def signature_statement(
    *,
    msg_id: str,
    link: str,
    generation: int,
    seq: int,
    segment: str,
    digest: str,
) -> dict[str, Any]:
    return {
        "purpose": SIGNATURE_PURPOSE,
        "v": SIGNATURE_VERSION,
        "msg_id": msg_id,
        "link": link,
        "generation": generation,
        "seq": seq,
        "segment": segment,
        "digest": digest,
    }


def sign_approval(seed: bytes, agent_id: str, statement: dict[str, Any]) -> str:
    key = derive_agent_key(seed, agent_id)
    body = b"trustrelay/approval/v1:" + canonical_bytes(statement)
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_approval(
    seed: bytes, agent_id: str, statement: dict[str, Any], signature: str
) -> bool:
    return hmac.compare_digest(sign_approval(seed, agent_id, statement), signature)


def is_int(value: Any) -> bool:
    """True for real integers only (``bool`` is rejected)."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX_DIGITS


def _safe_sort_key(item: Any) -> str:
    try:
        return canonical_bytes(item).decode("utf-8")
    except (TypeError, ValueError):
        return f"\x00{type(item).__name__}:{item!r}"


def canonicalize_event(event: Any) -> Any:
    """Make approval order irrelevant; malformed lists are left untouched."""
    if not isinstance(event, dict):
        return event
    if event.get("kind") != "submit_message":
        return dict(event)
    copy = dict(event)
    approvals = copy.get("approvals")
    if isinstance(approvals, list):
        copy["approvals"] = sorted(approvals, key=_safe_sort_key)
    return copy


def request_fingerprint(event: dict[str, Any]) -> str:
    """Fingerprint of the canonical submitted event (retry identity)."""
    return sha256_hex(canonical_bytes(event))


def record_digest(seq: int, prev: str, event: Any, outcome: Any) -> str:
    return sha256_hex(
        canonical_bytes({"seq": seq, "prev": prev, "event": event, "outcome": outcome})
    )


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Approval:
    agent: str
    sig: str

    def as_dict(self) -> dict[str, str]:
        return {"agent": self.agent, "sig": self.sig}


@dataclass
class MessageRecord:
    msg_id: str
    request_key: str
    link: str
    generation: int
    seq: int
    segment: str
    digest: str
    payload: Any
    approvals: tuple[Approval, ...]
    valid_agents: tuple[str, ...]
    sources_at_publish: tuple[str, ...]
    log_seq: int
    provable_sources: tuple[str, ...] = ()
    late_receipt: bool = False

    def fingerprint(self) -> str:
        """Stable identity used to compare full and incremental rebuilds."""
        body = {
            "msg_id": self.msg_id,
            "link": self.link,
            "generation": self.generation,
            "seq": self.seq,
            "segment": self.segment,
            "digest": self.digest,
            "approvals": [a.as_dict() for a in self.approvals],
            "sources": list(self.sources_at_publish),
            "provable": list(self.provable_sources),
        }
        return sha256_hex(canonical_bytes(body))


@dataclass(frozen=True)
class ReceiptRecord:
    receipt_id: str
    msg_id: str
    link: str
    generation: int
    digest: str
    late: bool
    log_seq: int


@dataclass(frozen=True)
class Outcome:
    log_seq: int
    kind: str
    status: str  # accepted | rejected | duplicate
    reason: str | None = None
    msg_id: str | None = None
    request_key: str | None = None
    receipt_id: str | None = None
    late: bool | None = None
    original_status: str | None = None
    original_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "log_seq": self.log_seq,
            "kind": self.kind,
            "status": self.status,
            "reason": self.reason,
            "msg_id": self.msg_id,
            "request_key": self.request_key,
            "receipt_id": self.receipt_id,
            "late": self.late,
            "original_status": self.original_status,
            "original_reason": self.original_reason,
        }


@dataclass
class JournalRecord:
    seq: int
    prev: str
    event: Any
    outcome: dict[str, Any]
    digest: str
    offset: int = 0


@dataclass
class JournalView:
    records: list[JournalRecord] = field(default_factory=list)
    torn_tail_bytes: int = 0
    chain_ok: bool = True
    chain_error: str | None = None
    head: str = GENESIS
    file_size: int = 0


class JournalIntegrityError(RuntimeError):
    pass


class ReplyLost(RuntimeError):
    """Raised after a durable commit when the caller's reply path is severed."""

    def __init__(self, outcome: Outcome):
        super().__init__(f"reply lost after durable commit: {outcome.msg_id}")
        self.outcome = outcome
