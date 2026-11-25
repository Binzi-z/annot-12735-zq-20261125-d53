"""Command-line entry point: ``python -m trustrelay <command>``.

Commands
    audit <store-dir>
        Independently re-parse and re-verify the journal on disk, print the
        visible messages, per-lease watermarks and every recorded rejection
        reason, and list any divergence from what was recorded.

    footprint <store-dir>
        Print the per-partition fingerprints the auditor derives from bytes.

This tool never trusts the runtime: it reads only ``relay.meta.json`` and
``relay.journal`` and applies its own rule set (``trustrelay.verify``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .verify import audit_store


def _audit(store: Path) -> int:
    report = audit_store(store)
    summary = report.as_dict()
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    print("\nvisible messages:")
    for msg in report.visible:
        print(
            f"  {msg.link}@{msg.generation} seq={msg.seq:<6} {msg.msg_id:<24} "
            f"segment={msg.segment} agents={','.join(msg.agents)} "
            f"sources={','.join(msg.sources)} "
            f"provable={','.join(msg.provable_sources) or '-'}"
        )

    print("\nleases:")
    for key, info in report.leases.items():
        print(
            f"  {key:<10} status={info['status']:<8} watermark={info['watermark']:<6} "
            f"provable_watermark={info['provable_watermark']:<6} "
            f"agents={','.join(info['agents'])}"
        )

    print("\nrejections (durable reasons):")
    for rej in report.rejections:
        print(
            f"  log_seq={rej['log_seq']:<6} {rej['kind']:<15} "
            f"msg={rej['msg_id'] or '-':<20} reason={rej['reason']}"
        )

    if report.receipts:
        print("\nreceipts:")
        for rec in report.receipts:
            print(
                f"  {rec['receipt_id']:<12} msg={rec['msg_id']:<20} "
                f"late={rec['late']} log_seq={rec['log_seq']}"
            )

    if summary["divergences"]:
        print("\nDIVERGENCES FOUND:", file=sys.stderr)
        for line in summary["divergences"]:
            print("  " + line, file=sys.stderr)
        return 1
    if not report.chain_ok:
        print(f"\nCHAIN INVALID: {report.chain_error}", file=sys.stderr)
        return 1
    print("\nOK: journal chain valid, every recorded decision re-derived identically.")
    return 0


def _footprint(store: Path) -> int:
    report = audit_store(store)
    print(json.dumps(report.footprint, indent=2, ensure_ascii=False))
    return 0 if report.chain_ok and not report.divergences else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2 or args[0] not in {"audit", "footprint"}:
        print(__doc__)
        return 2
    store = Path(args[1])
    if not (store / "relay.journal").exists():
        print(f"not a relay store: {store}", file=sys.stderr)
        return 2
    return _audit(store) if args[0] == "audit" else _footprint(store)


if __name__ == "__main__":
    raise SystemExit(main())
