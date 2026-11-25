"""Shared helpers for the relay test-suite."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from trustrelay.events import message_event, receipt_event, scripted_seed  # noqa: E402
from trustrelay.model import payload_digest  # noqa: E402
from trustrelay.state import RelayRuntime  # noqa: E402

SEED = scripted_seed("suite")


def open_lease(rt, link, gen):
    return rt.submit({"kind": "open_lease", "link": link, "generation": gen})


def register(rt, agent, source, link, gen):
    return rt.submit(
        {
            "kind": "register_agent",
            "agent": agent,
            "control_source": source,
            "link": link,
            "generation": gen,
        }
    )


def activate(rt, link, gen):
    return rt.submit({"kind": "activate_lease", "link": link, "generation": gen})


def migrate(rt, s_link, s_gen, t_link, t_gen):
    return rt.submit(
        {
            "kind": "migrate",
            "source_link": s_link,
            "from_generation": s_gen,
            "target_link": t_link,
            "to_generation": t_gen,
        }
    )


def revoke(rt, agent):
    return rt.submit({"kind": "revoke_agent", "agent": agent})


def make_message(
    rt,
    *,
    msg_id,
    link,
    gen,
    seq,
    signers,
    payload=None,
    request_key=None,
    segment=None,
    digest=None,
    seed=SEED,
):
    payload = {"msg_id": msg_id, "seq": seq} if payload is None else payload
    return message_event(
        seed=seed,
        request_key=request_key or f"req-{msg_id}",
        msg_id=msg_id,
        link=link,
        generation=gen,
        seq=seq,
        payload=payload,
        signers=signers,
        segment=segment,
        digest=digest,
    )


def setup_link(rt, link, gen, agents, seed=SEED):
    """Open + register + activate one lease.  ``agents`` is [(id, source), ...]."""
    open_lease(rt, link, gen)
    for agent, source in agents:
        register(rt, agent, source, link, gen)
    return activate(rt, link, gen)


def setup_two_links(rt, seed=SEED):
    """L1g1 active; L2g1 staged and ready as a migration target."""
    setup_link(rt, "L1", 1, [("a1", "srcA"), ("b1", "srcB")], seed=seed)
    open_lease(rt, "L2", 1)
    register(rt, "a2", "srcA2", "L2", 1)
    register(rt, "b2", "srcB2", "L2", 1)


__all__ = [
    "SEED",
    "RelayRuntime",
    "message_event",
    "receipt_event",
    "payload_digest",
    "open_lease",
    "register",
    "activate",
    "migrate",
    "revoke",
    "make_message",
    "setup_link",
    "setup_two_links",
]
