"""Offline trust-lease relay state and an independent verifier.

Two isolated edge links switch trust proxies during a maintenance window.
Messages only move through a local synthetic queue - here, a checksum-chained
append-only journal.  Standard library only; runs on Windows Python 3.12.

Public surface
    RelayRuntime   journal-backed runtime (append + fsync + replay)
    RelayState     pure decision/apply core
    audit_store    independent on-disk verifier (does not import RelayState)

Approval signatures are a deterministic HMAC model for offline testing; they
are not a production signature scheme.
"""

from __future__ import annotations

from .journal import Journal, read_journal
from .model import (
    Approval,
    JournalIntegrityError,
    MessageRecord,
    Outcome,
    ReceiptRecord,
    ReplyLost,
)
from .state import AgentState, Lease, RelayRuntime, RelayState, RevocationStats
from .verify import AuditReport, audit_store, compare_with_runtime

__version__ = "1.0.0"

__all__ = [
    "RelayRuntime",
    "RelayState",
    "Lease",
    "AgentState",
    "RevocationStats",
    "Journal",
    "read_journal",
    "Outcome",
    "MessageRecord",
    "ReceiptRecord",
    "Approval",
    "ReplyLost",
    "JournalIntegrityError",
    "audit_store",
    "compare_with_runtime",
    "AuditReport",
    "__version__",
]
