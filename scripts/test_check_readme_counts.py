#!/usr/bin/env python3
"""Regression tests for the README count claims check_readme_counts.py reads.

Each test runs check_readme_counts.main() against a copy of the shipped
README.md with one count claim changed, and the shipped fixtures/ and
docs/fixtures.md.

Run from the repository root:
    python3 scripts/test_check_readme_counts.py -v
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import check_readme_counts as crc

SHIPPED = crc.README.read_text(encoding="utf-8")
OUTCOMES = [
    json.loads(path.read_text(encoding="utf-8"))["expected"]["verifyResult"]
    for path in sorted(crc.FIXTURES.glob("*.json"))
]
N = len(OUTCOMES)
ACCEPT = OUTCOMES.count("ACCEPT")
REJECT = OUTCOMES.count("REJECT")


def line_of(needle: str) -> int:
    """1-based README line of the single occurrence of `needle`."""
    assert SHIPPED.count(needle) == 1, f"{needle!r} occurs {SHIPPED.count(needle)} times"
    return SHIPPED.count("\n", 0, SHIPPED.index(needle)) + 1


def mutate(needle: str, replacement: str) -> str:
    line_of(needle)
    return SHIPPED.replace(needle, replacement)


def run_with_readme(text: str) -> tuple[int, str]:
    """main()'s exit code and stderr with README.md replaced by `text`."""
    with tempfile.TemporaryDirectory() as tmp:
        readme = pathlib.Path(tmp) / "README.md"
        readme.write_text(text, encoding="utf-8")
        err = io.StringIO()
        with mock.patch.object(crc, "README", readme), contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(err):
            code = crc.main()
    return code, err.getvalue()


class ReadmeCountsTest(unittest.TestCase):
    def assertFailsAt(self, text: str, line: int, message: str) -> None:
        code, err = run_with_readme(text)
        self.assertEqual(code, 1, err)
        self.assertIn(f"README.md:{line}: {message}", err)

    def test_shipped_readme_passes(self) -> None:
        code, err = run_with_readme(SHIPPED)
        self.assertEqual(code, 0, err)

    def test_summary_counts_are_read(self) -> None:
        needle = f"summary: {N} pass, 0 fail ({N} fixtures)"
        text = mutate(needle, f"summary: {N - 1} pass, 0 fail ({N - 1} fixtures)")
        self.assertFailsAt(text, line_of(needle), f"README claims `{N - 1} pass`")
        self.assertFailsAt(text, line_of(needle), f"README claims {N - 1} fixtures")

    def test_summary_fixture_count_alone_is_read(self) -> None:
        needle = f"({N} fixtures)"
        text = mutate(needle, f"({N - 1} fixtures)")
        self.assertFailsAt(text, line_of(needle), f"README claims {N - 1} fixtures")

    def test_summary_fail_count_is_read(self) -> None:
        needle = f"summary: {N} pass, 0 fail"
        text = mutate(needle, f"summary: {N} pass, 1 fail")
        self.assertFailsAt(text, line_of(needle), "README claims `1 fail`, expected 0")

    def test_accept_reject_split_is_read(self) -> None:
        needle = f"({ACCEPT} ACCEPT, {REJECT} REJECT)"
        text = mutate(needle, f"({ACCEPT + 1} ACCEPT, {REJECT - 1} REJECT)")
        self.assertFailsAt(
            text, line_of(needle), f"README claims {ACCEPT + 1} ACCEPT, {REJECT - 1} REJECT"
        )

    def test_missing_accept_reject_split_is_reported(self) -> None:
        code, err = run_with_readme(mutate(f" ({ACCEPT} ACCEPT, {REJECT} REJECT)", ""))
        self.assertEqual(code, 1, err)
        self.assertIn("no `(N ACCEPT, M REJECT)` claim found in README", err)

    def test_cosigner_example_is_read(self) -> None:
        needle = f"python={N} pass, 0 fail"
        text = mutate(needle, f"python={N - 1} pass, 0 fail")
        self.assertFailsAt(text, line_of(needle), f"README claims `{N - 1} pass`")

    def test_wrapped_pass_fail_claim_is_read(self) -> None:
        needle = f"`{N} pass, 0 fail`"
        text = mutate(needle, f"`{N - 1} pass,\n   0 fail`")
        self.assertFailsAt(text, line_of(needle), f"README claims `{N - 1} pass`")

    def test_table_row_names_its_line(self) -> None:
        needle = f"ML-DSA-65 | {N} / {N} PASS"
        text = mutate(needle, f"ML-DSA-65 | {N - 1} / {N - 1} PASS")
        self.assertFailsAt(
            text, line_of(needle), f"README implementations table claims {N - 1} / {N - 1} PASS"
        )


if __name__ == "__main__":
    unittest.main()
