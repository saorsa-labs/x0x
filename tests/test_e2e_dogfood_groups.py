#!/usr/bin/env python3
"""Offline redaction controls for the local groups + contacts dogfood harness."""
from __future__ import annotations

import importlib.util
import io
import json
import logging
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


SECRET = "Bearer token-secret-value"


def load_dogfood():
    tests_dir = Path(__file__).parent
    sys.path.insert(0, str(tests_dir))
    spec = importlib.util.spec_from_file_location(
        "e2e_dogfood_groups", tests_dir / "e2e_dogfood_groups.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DogfoodReportRedactionTests(unittest.TestCase):
    """Report rows never persist raw HTTP bodies, exception text or tokens."""

    @classmethod
    def setUpClass(cls):
        cls.dogfood = load_dogfood()

    def _harness(self, perform_error):
        dogfood = self.dogfood

        class Client:
            def perform(self, _action, _params):
                raise perform_error

        anchor = "a" * 64
        log = logging.getLogger("dogfood-redaction")
        return dogfood.DogfoodHarness(
            Client(), dogfood.ResultRouter(log), anchor,
            {"alice": dogfood.Runner("alice", anchor)}, log,
        )

    def test_http_error_keeps_status_and_class_only(self):
        # Codex #1021 P1: lowercase token-like and hex "reason"/"code" values
        # passed the old character filter. No body field may be kept.
        body = json.dumps({"ok": False, "error": SECRET, "reason": "token_secret_value",
                           "code": "deadbeef" * 8}).encode()
        error = urllib.error.HTTPError("http://127.0.0.1/contacts", 403, SECRET, {},
                                       io.BytesIO(body))
        self.addCleanup(error.close)
        response = self._harness(error).call("alice", "contact_add", {"agent_id": "b" * 64})
        self.assertEqual({"error_class": "HTTPError", "http_status": 403}, response["outcome"])
        for leaked in ("token-secret-value", "token_secret_value", "deadbeef"):
            self.assertNotIn(leaked, json.dumps(response))

    def test_generic_exception_keeps_class_only(self):
        response = self._harness(RuntimeError(SECRET)).call("alice", "contact_list")
        self.assertEqual({"error_class": "RuntimeError"}, response["outcome"])
        self.assertNotIn("token-secret-value", json.dumps(response))

    def test_unlisted_exception_class_is_other(self):
        class TokenSecretValueError(Exception):
            pass
        response = self._harness(TokenSecretValueError(SECRET)).call("alice", "contact_list")
        self.assertEqual({"error_class": "Other"}, response["outcome"])

    def test_written_report_keeps_scenario_crash_class_only(self):
        dogfood = self.dogfood

        class Client:
            def __init__(self, _base, _token):
                pass

            def health(self):
                return {"ok": True}

            def agent(self):
                return {"agent_id": "a" * 64}

        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            argv = ["--api-base", "http://127.0.0.1:1", "--api-token", "t",
                    "--runner", f"bob:{'b' * 64}", "--report", str(report)]
            with mock.patch.object(dogfood, "X0xClient", Client), \
                    mock.patch.object(dogfood.threading, "Thread"), \
                    mock.patch.object(dogfood.time, "sleep"), \
                    mock.patch.object(dogfood.DogfoodHarness, "run_contacts_lifecycle",
                                      side_effect=RuntimeError(SECRET)), \
                    self.assertLogs("e2e_dogfood_groups", level=logging.ERROR):
                self.assertEqual(1, dogfood.main(argv))
            text = report.read_text()
        self.assertIn("scenario crash: RuntimeError", json.loads(text)["failures"])
        self.assertNotIn("token-secret-value", text)


if __name__ == "__main__":
    unittest.main()
