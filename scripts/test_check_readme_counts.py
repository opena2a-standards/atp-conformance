#!/usr/bin/env python3
"""Regression tests for the README count claims and unit-suite commands
check_readme_counts.py reads.

Each test runs check_readme_counts.main() against a copy of the shipped
README.md with a count claim or unit-suite command changed, a copy of
.github/workflows/conformance.yml, and the shipped fixtures/ and
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
WORKFLOW = crc.WORKFLOW.read_text(encoding="utf-8")
GO_SUITE = "(cd verifiers/go && go test ./...)\n"
PYTHON_SUITE = "(cd verifiers/python && python3 -m unittest test_verify)\n"
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


def run_with_readme(text: str, workflow: str = WORKFLOW) -> tuple[int, str]:
    """main()'s exit code and stderr with README.md replaced by `text` and
    conformance.yml by `workflow`."""
    with tempfile.TemporaryDirectory() as tmp:
        readme = pathlib.Path(tmp) / "README.md"
        readme.write_text(text, encoding="utf-8")
        conformance = pathlib.Path(tmp) / "conformance.yml"
        conformance.write_text(workflow, encoding="utf-8")
        err = io.StringIO()
        with mock.patch.object(crc, "README", readme), mock.patch.object(
            crc, "WORKFLOW", conformance
        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = crc.main()
    return code, err.getvalue()


class ReadmeCountsTest(unittest.TestCase):
    def assertFailsAt(
        self, text: str, line: int, message: str, workflow: str = WORKFLOW
    ) -> None:
        code, err = run_with_readme(text, workflow)
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

    def test_unit_suite_the_workflow_does_not_run_must_be_given(self) -> None:
        heading = line_of(f"## {crc.CI_SECTION}\n")
        suites = (("verifiers/go", GO_SUITE), ("verifiers/python", PYTHON_SUITE))
        for directory, suite in suites:
            with self.subTest(directory=directory):
                self.assertFailsAt(
                    mutate(suite, ""),
                    heading,
                    f"conformance.yml does not run the {directory} unit suite",
                )

    def test_unit_suite_the_workflow_runs_must_not_be_given(self) -> None:
        self.assertFailsAt(
            SHIPPED,
            line_of(GO_SUITE),
            "conformance.yml runs the verifiers/go unit suite",
            WORKFLOW + "        run: go test -v ./...\n",
        )

    def test_unit_suite_the_workflow_runs_may_be_left_out(self) -> None:
        workflow = WORKFLOW + "        run: python3 -m unittest -v test_verify\n"
        code, err = run_with_readme(mutate(PYTHON_SUITE, ""), workflow)
        self.assertEqual(code, 0, err)

    def test_workflow_comment_is_not_a_run(self) -> None:
        code, err = run_with_readme(SHIPPED, WORKFLOW + "  # go test ./... and test_verify\n")
        self.assertEqual(code, 0, err)

    def test_command_outside_the_section_code_blocks_is_not_given(self) -> None:
        heading = f"## {crc.CI_SECTION}\n"
        without = mutate(GO_SUITE, "")
        cases = {
            "inline in the section": without.replace(
                heading, f"{heading}\nRun `go test ./...` in verifiers/go.\n"
            ),
            "in a later section": f"{without}\n```bash\n{GO_SUITE}```\n",
        }
        for case, text in cases.items():
            with self.subTest(case=case):
                self.assertFailsAt(
                    text,
                    line_of(heading),
                    "conformance.yml does not run the verifiers/go unit suite",
                )

    def test_missing_ci_section_is_reported(self) -> None:
        code, err = run_with_readme(mutate(f"## {crc.CI_SECTION}\n", "## CI\n"))
        self.assertEqual(code, 1, err)
        self.assertIn(f"no `## {crc.CI_SECTION}` section found in README", err)


if __name__ == "__main__":
    unittest.main()
