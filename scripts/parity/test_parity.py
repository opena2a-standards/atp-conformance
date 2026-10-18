#!/usr/bin/env python3
"""Regression tests for the parity gate's checks on the Go verifier's
built-in fixture set and on a verifier run that reports no fixtures.

The built-in set tests compare temporary copies of the shipped fixtures/
with one file changed, removed or added. The main() tests replace the
verifier runs with canned records, so they need no Go or Python verifier.

Run from the repository root:
    python3 scripts/parity/test_parity.py -v
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import parity

NAMES = sorted(p.name for p in parity.FIXTURES.glob("*.json"))


def passing_records() -> dict[str, dict]:
    return {n: {"gate": "PASS", "verdict": "ACCEPT", "category": None} for n in NAMES}


def run_main(copy: pathlib.Path, runs: dict[str, tuple[int, dict]]) -> tuple[int, str]:
    """main()'s exit code and stdout with the built-in copy at `copy` and each
    verifier run answered from `runs`."""
    out = io.StringIO()
    with mock.patch.object(parity, "BUILTIN_COPY", copy), mock.patch.object(
        parity, "run_verifier", side_effect=lambda name, spec: runs[name]
    ), mock.patch.object(sys, "argv", ["parity.py"]), contextlib.redirect_stdout(out):
        code = parity.main()
    return code, out.getvalue()


class BuiltinCopyTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.copy = pathlib.Path(tmp.name) / "fixtures"
        shutil.copytree(parity.FIXTURES, self.copy)

    def divergences(self) -> list[str]:
        return parity.builtin_copy_divergences(parity.FIXTURES, self.copy)

    def test_shipped_copy_matches(self) -> None:
        self.assertGreater(len(NAMES), 0)
        self.assertEqual(parity.builtin_copy_divergences(parity.FIXTURES, parity.BUILTIN_COPY), [])

    def test_exact_copy_matches(self) -> None:
        self.assertEqual(self.divergences(), [])

    def test_changed_byte_is_reported(self) -> None:
        target = self.copy / NAMES[0]
        data = bytearray(target.read_bytes())
        data[-2] ^= 0x01
        target.write_bytes(bytes(data))
        [got] = self.divergences()
        self.assertIn(f"{NAMES[0]} differs from fixtures/{NAMES[0]}", got)
        self.assertIn(f"fix: cp fixtures/{NAMES[0]}", got)

    def test_missing_file_is_reported(self) -> None:
        (self.copy / NAMES[-1]).unlink()
        [got] = self.divergences()
        self.assertIn(f"{NAMES[-1]} is missing", got)

    def test_extra_file_is_reported(self) -> None:
        (self.copy / "not-a-fixture.json").write_text("{}\n", encoding="utf-8")
        [got] = self.divergences()
        self.assertIn("not-a-fixture.json is not in fixtures/", got)

    def test_main_fails_on_a_changed_copy(self) -> None:
        target = self.copy / NAMES[0]
        target.write_bytes(target.read_bytes() + b"\n")
        runs = {name: (0, passing_records()) for name in parity.VERIFIERS}
        code, out = run_main(self.copy, runs)
        self.assertEqual(code, 1, out)
        self.assertIn("PARITY: FAIL", out)
        self.assertIn(f"{NAMES[0]} differs from fixtures/{NAMES[0]}", out)

    def test_main_passes_when_every_run_agrees(self) -> None:
        runs = {name: (0, passing_records()) for name in parity.VERIFIERS}
        code, out = run_main(self.copy, runs)
        self.assertEqual(code, 0, out)


class VerifierRunTest(unittest.TestCase):
    def test_every_verifier_runs(self) -> None:
        self.assertEqual(sorted(parity.VERIFIERS), ["go", "go-builtin", "python"])
        self.assertEqual(parity.VERIFIERS["go-builtin"]["cmd"], ["go", "run", "."])

    def test_main_fails_when_one_run_reports_no_fixtures(self) -> None:
        for silent in parity.VERIFIERS:
            with self.subTest(silent=silent):
                runs = {name: (0, passing_records()) for name in parity.VERIFIERS}
                runs[silent] = (0, {})
                code, out = run_main(parity.BUILTIN_COPY, runs)
                self.assertEqual(code, 1, out)
                self.assertIn(f"{silent} fixture set mismatch", out)


if __name__ == "__main__":
    unittest.main()
