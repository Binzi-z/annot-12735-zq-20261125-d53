"""Convenience constructors for synthetic relay traffic.

Produces fully-signed, canonical events so tooling and tests never have to
hand-assemble MAC statements.  The seed is the same synthetic master seed used
by the relay; callers keep it in memory or in the test store directory.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from .model import (
    payload_digest,
    sign_approval,
    signature_statement,
)


def digest_of(payload: Any) -> str:
    return payload_digest(payload)


def approval(seed: bytes, agent: str, *, event: dict[str, Any]) -> dict[str, str]:
    statement = signature_statement(
        msg_id=event["msg_id"],
        link=event["link"],
        generation=event["generation"],
        seq=event["seq"],
        segment=event["segment"],
        digest=event["digest"],
    )
    return {"agent": agent, "sig": sign_approval(seed, agent, statement)}


def message_event(
    *,
    seed: bytes,
    request_key: str,
    msg_id: str,
    link: str,
    generation: int,
    seq: int,
    payload: Any,
    signers: Iterable[str],
    segment: str | None = None,
    digest: str | None = None,
) -> dict[str, Any]:
    body = {
        "kind": "submit_message",
        "request_key": request_key,
        "msg_id": msg_id,
        "link": link,
        "generation": generation,
        "seq": seq,
        "segment": segment if segment is not None else f"seg-{seq:06d}",
        "payload": payload,
        "digest": digest if digest is not None else digest_of(payload),
    }
    body["approvals"] = [approval(seed, agent, event=body) for agent in signers]
    return body


def receipt_event(
    *,
    receipt_id: str,
    msg_id: str,
    link: str,
    generation: int,
    digest: str,
) -> dict[str, Any]:
    return {
        "kind": "submit_receipt",
        "receipt_id": receipt_id,
        "msg_id": msg_id,
        "link": link,
        "generation": generation,
        "digest": digest,
    }


def scripted_seed(label: str) -> bytes:
    """Deterministic per-scenario seed (test-only)."""
    return hashlib.sha256(b"trustrelay/seed/" + label.encode("utf-8")).digest()
