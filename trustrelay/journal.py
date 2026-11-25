"""Append-only, checksum-chained journals.

A store has two physical files:

``relay.journal``
    One canonical-JSON record per line:
    ``{"seq", "prev", "event", "outcome", "digest"}``.  ``digest`` covers
    seq/prev/event/outcome and the next record's ``prev`` is this digest.  A
    crash can leave at most one torn tail line; readers stop at the first
    incomplete or invalid line and report how many trailing bytes were
    ignored.

``relay.meta.json``
    Store metadata (format version, synthetic master seed, store nonce),
    written once with fsync + atomic replace.

Durability protocol for every append: write one full line, flush, fsync (when
enabled), then return the outcome.  Replies are only produced after the append
returns, which is why the "commit then lose the reply" scenario can rebuild
committed state from the journal alone.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .model import (
    GENESIS,
    JournalIntegrityError,
    JournalRecord,
    JournalView,
    canonical_bytes,
    record_digest,
    sha256_hex,
)

FORMAT_VERSION = 1
MAX_LINE_BYTES = 8 * 1024 * 1024


def _fsync_dir(path: Path) -> None:
    """Best-effort directory fsync (POSIX).  Windows has no directory fsync."""
    if os.name != "posix":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


class Journal:
    def __init__(self, journal_path: Path, meta_path: Path, seed: bytes, *, fsync: bool = True):
        self.journal_path = Path(journal_path)
        self.meta_path = Path(meta_path)
        self.seed = seed
        self.fsync = fsync
        self._handle = None
        self._head = GENESIS
        self._next_seq = 1

    # -- creation / opening ------------------------------------------------
    @classmethod
    def create(
        cls,
        journal_path: Path,
        meta_path: Path,
        seed: bytes,
        *,
        fsync: bool = True,
    ) -> "Journal":
        journal_path = Path(journal_path)
        meta_path = Path(meta_path)
        if journal_path.exists() or meta_path.exists():
            raise FileExistsError("store already exists")
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "format": FORMAT_VERSION,
            "seed_hex": seed.hex(),
            "store_nonce": sha256_hex(seed + b"/store-nonce"),
        }
        atomic_write_bytes(meta_path, canonical_bytes(meta) + b"\n")
        atomic_write_bytes(journal_path, b"")
        journal = cls(journal_path, meta_path, seed, fsync=fsync)
        journal._open_for_append(GENESIS, 1)
        return journal

    @classmethod
    def open_existing(
        cls, journal_path: Path, meta_path: Path, *, fsync: bool = True
    ) -> "Journal":
        meta_path = Path(meta_path)
        meta = json.loads(meta_path.read_bytes().decode("utf-8"))
        if meta.get("format") != FORMAT_VERSION:
            raise JournalIntegrityError(f"unsupported store format: {meta.get('format')!r}")
        seed = bytes.fromhex(meta["seed_hex"])
        journal = cls(journal_path, meta_path, seed, fsync=fsync)
        view = journal.scan()
        if not view.chain_ok:
            raise JournalIntegrityError(view.chain_error or "journal chain invalid")
        if view.torn_tail_bytes:
            journal._truncate_torn_tail(view)
        head = view.records[-1].digest if view.records else GENESIS
        next_seq = view.records[-1].seq + 1 if view.records else 1
        journal._open_for_append(head, next_seq)
        return journal

    def _open_for_append(self, head: str, next_seq: int) -> None:
        self._handle = open(self.journal_path, "ab")
        self._handle.seek(0, os.SEEK_END)
        self._head = head
        self._next_seq = next_seq

    # -- scan --------------------------------------------------------------
    def scan(self) -> JournalView:
        view = JournalView()
        try:
            data = self.journal_path.read_bytes()
        except FileNotFoundError:
            return view
        view.file_size = len(data)
        offset = 0
        expected_seq = 1
        prev = GENESIS
        while offset < len(data):
            newline = data.find(b"\n", offset)
            if newline < 0:
                view.torn_tail_bytes = len(data) - offset
                break
            line = data[offset:newline]
            if len(line) > MAX_LINE_BYTES or b"\x00" in line:
                view.chain_ok = False
                view.chain_error = f"bad line at offset {offset}"
                view.torn_tail_bytes = len(data) - offset
                break
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                view.chain_ok = False
                view.chain_error = f"undecodable record at offset {offset}: {exc}"
                view.torn_tail_bytes = len(data) - offset
                break
            if not isinstance(record, dict):
                view.chain_ok = False
                view.chain_error = f"record is not an object at offset {offset}"
                view.torn_tail_bytes = len(data) - offset
                break
            seq = record.get("seq")
            if seq != expected_seq:
                view.chain_ok = False
                view.chain_error = (
                    f"sequence break at offset {offset}: expected {expected_seq}, got {seq!r}"
                )
                view.torn_tail_bytes = len(data) - offset
                break
            if record.get("prev") != prev:
                view.chain_ok = False
                view.chain_error = f"prev-hash break at seq {seq}"
                view.torn_tail_bytes = len(data) - offset
                break
            digest = record.get("digest")
            recomputed = record_digest(seq, prev, record.get("event"), record.get("outcome"))
            if digest != recomputed:
                view.chain_ok = False
                view.chain_error = f"digest mismatch at seq {seq}"
                view.torn_tail_bytes = len(data) - offset
                break
            view.records.append(
                JournalRecord(
                    seq=seq,
                    prev=prev,
                    event=record["event"],
                    outcome=record["outcome"],
                    digest=digest,
                    offset=offset,
                )
            )
            prev = digest
            expected_seq += 1
            offset = newline + 1
        view.head = prev
        return view

    def _truncate_torn_tail(self, view: JournalView) -> None:
        keep = view.file_size - view.torn_tail_bytes
        with open(self.journal_path, "r+b") as handle:
            handle.truncate(keep)
            handle.flush()
            os.fsync(handle.fileno())

    # -- append ------------------------------------------------------------
    def append(self, event: Any, outcome: dict[str, Any]) -> JournalRecord:
        if self._handle is None:
            raise JournalIntegrityError("journal is not open for append")
        seq = self._next_seq
        prev = self._head
        digest = record_digest(seq, prev, event, outcome)
        record = {"seq": seq, "prev": prev, "event": event, "outcome": outcome, "digest": digest}
        line = canonical_bytes(record) + b"\n"
        offset = self._handle.tell()
        self._handle.write(line)
        self._handle.flush()
        if self.fsync:
            os.fsync(self._handle.fileno())
        self._head = digest
        self._next_seq = seq + 1
        return JournalRecord(
            seq=seq, prev=prev, event=event, outcome=outcome, digest=digest, offset=offset
        )

    def head(self) -> str:
        return self._head

    def next_seq(self) -> int:
        return self._next_seq

    def close(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            if self.fsync:
                os.fsync(self._handle.fileno())
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "Journal":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def read_journal(journal_path: Path) -> JournalView:
    """Scan a journal without holding the append handle."""
    return Journal(journal_path, journal_path.with_suffix(".meta.json"), b"").scan()
