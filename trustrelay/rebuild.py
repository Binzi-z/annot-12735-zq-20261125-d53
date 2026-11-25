"""Full re-derivation of proof state, for comparison against local updates.

The runtime keeps a per-agent message index, so a single revocation only
re-evaluates the messages that agent co-signed (:meth:`RelayState._revoke`).
This module provides the naive alternative: sweep *every* message in *every*
lease and recompute each partition's provable sources and watermark.  The
benchmark uses it as the "full rebuild" baseline.

It produces exactly the same final state as the local path; only the amount of
work differs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .state import RelayState


@dataclass(frozen=True)
class RebuildStats:
    messages: int
    partitions: int
    segments: int


def full_rebuild(state: RelayState) -> RebuildStats:
    """Recompute provable sources/watermarks for all leases from scratch."""
    messages = 0
    segments: set[tuple[str, int, str]] = set()
    partitions = 0
    for (link, generation), lease in state.leases.items():
        partitions += 1
        first_unprovable: int | None = None
        for seq in range(1, lease.watermark + 1):
            msg_id = lease.by_seq.get(seq)
            if msg_id is None:  # pragma: no cover - sequence is contiguous
                first_unprovable = first_unprovable or seq
                continue
            msg = state.messages[msg_id]
            messages += 1
            segments.add((link, generation, msg.segment))
            survivors = [a for a in msg.valid_agents if not state.agents[a].revoked]
            msg.provable_sources = tuple(
                sorted({state.agents[a].control_source for a in survivors})
            )
            if not msg.provable_sources and first_unprovable is None:
                first_unprovable = seq
        lease.provable_watermark = (
            first_unprovable - 1 if first_unprovable is not None else lease.watermark
        )
    return RebuildStats(messages=messages, partitions=partitions, segments=len(segments))


__all__ = ["RebuildStats", "full_rebuild"]
