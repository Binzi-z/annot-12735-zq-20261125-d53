"""End-to-end demonstration: build a store, then audit it via the CLI module.

This keeps the CLI path exercised by the test-suite (so ``python -m trustrelay
audit`` stays working) while also producing a human-readable transcript at
``artifacts/audit_demo.txt``.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tests.support import SEED, make_message, migrate, revoke, setup_link, setup_two_links
from trustrelay.__main__ import main as cli_main
from trustrelay.events import receipt_event
from trustrelay.state import RelayRuntime


class CliAuditDemo(unittest.TestCase):
    def test_cli_audit_reports_visible_messages_and_reasons(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        try:
            rt = RelayRuntime.create(root, SEED, fsync=False)
            try:
                setup_two_links(rt)
                ev1 = make_message(
                    rt, msg_id="m1", link="L1", gen=1, seq=1, signers=["a1", "b1"]
                )
                self.assertEqual(rt.submit(ev1).status, "accepted")
                # A rejected submit whose reason must survive to disk.
                bad = make_message(
                    rt, msg_id="m2", link="L1", gen=1, seq=2, signers=["a1", "b1"]
                )
                bad["digest"] = "a" * 64
                rst = rt.submit(bad)
                self.assertEqual(rst.reason, "digest_mismatch")
                rt.submit(
                    receipt_event(
                        receipt_id="rc1",
                        msg_id="m1",
                        link="L1",
                        generation=1,
                        digest=ev1["digest"],
                    )
                )
                migrate(rt, "L1", 1, "L2", 1)
            finally:
                rt.close()

            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = cli_main(["audit", str(root)])
            self.assertEqual(code, 0, err.getvalue())
            text = out.getvalue()
            self.assertIn("visible messages:", text)
            self.assertIn("m1", text)
            self.assertIn("digest_mismatch", text)
            self.assertIn("OK: journal chain valid", text)

            out2 = io.StringIO()
            with redirect_stdout(out2), redirect_stderr(io.StringIO()):
                code2 = cli_main(["footprint", str(root)])
            self.assertEqual(code2, 0)
            fp = json.loads(out2.getvalue())
            self.assertIn("L1@1", fp)
            self.assertIn("L2@1", fp)

            artifacts = Path(__file__).resolve().parent.parent / "artifacts"
            artifacts.mkdir(exist_ok=True)
            (artifacts / "audit_demo.txt").write_text(
                text
                + "\nfootprint:\n"
                + out2.getvalue()
                + f"\nexit_codes: audit={code} footprint={code2}\n",
                encoding="utf-8",
            )
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
