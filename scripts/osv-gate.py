#!/usr/bin/env python3
"""Apply a severity policy to OSV-Scanner's JSON output.

Why this exists rather than a flag. OSV-Scanner has no severity threshold: it
exits 1 on any finding, whatever its severity. A gate built on that exit code
gates on *presence*, not on severity, and the first high-severity finding that
someone does not want to fix becomes an `IgnoredVulns` entry that nothing
reviews.

Why the analysis rule is what it is. OSV-Scanner's Rust call analysis is
experimental and its own documentation says an absent analysis object is **not**
the same as `called: false`: it may mean missing symbol metadata, an unsupported
construct, or a toolchain failure. On this repository the analysis cannot build
the workspace at all, so *every* finding arrives with no analysis entry.

A gate that failed only on `called: true` would therefore pass everything here,
forever, and look green. So the rule is:

    high or critical, and NOT explicitly called: false  ->  fail

Only an explicit `called: false` passes, and every pass is printed with its
advisory id and reason. A dismissal that is not printed is a dismissal nobody
can review.

Usage:
    osv-gate.py RESULTS.json [--fail-on high|critical|medium|low]

Exit codes:
    0  no finding at or above the threshold that reaches the code path
    1  a finding at or above the threshold reaches the code path
    2  the input could not be read or understood

The input is the file OSV-Scanner writes with `--format=json`. The shape this
reads, measured against v2.7.1:

    {"results": [{"source": {...},
                  "packages": [{"package": {"name", "version", ...},
                                "vulnerabilities": [{"id", "severity", ...}],
                                "groups": [...]}]}]}

`experimental_analysis` sits on the vulnerability when the analyser produced a
verdict, and is absent otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ordered worst-last so a comparison is a list index.
SEVERITIES = ["low", "medium", "high", "critical"]

# OSV records carry a CVSS vector rather than a label. The base score is what
# the vector's numbers imply; the mapping below is the CVSS v3 qualitative
# rating scale, which is what a reader expects "high" to mean.
CVSS_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def severity_of(vuln: dict) -> str:
    """The finding's severity as one of `SEVERITIES`, or `unknown`/`informational`.

    OSV records carry a CVSS vector on some entries and nothing on others,
    because severity is an upstream database field and RustSec does not always
    supply one. Two distinct absences are separated here, and conflating them was
    a bug in the first version of this script:

    * `informational` — the record says what kind of problem it is and the kind
      is not a code weakness: `unmaintained`, `unsound`, `yanked`. RustSec
      encodes these as advisory *classes*, and `cargo audit` reports them as
      warnings rather than vulnerabilities. Failing the gate on them would make
      an unmaintained build-dependency as urgent as a remote code execution, and
      the first person to hit it would add an ignore rather than a fix.

    * `unknown` — the record carries no severity and no class. This is treated as
      at least the threshold, because an unrated vulnerability is not a safe one.

    The class lives at `affected[].database_specific.informational`, not at the
    top level. Measured against v2.7.1: the top-level `database_specific` carries
    only a licence, and the class is one level down.

    `unsound` is deliberately *not* in the informational set for the gate: it is
    a real code weakness, and the advisory above names the affected functions.
    It is reported separately so a reader sees it, and it is treated as a
    finding when the analysis says the function is reachable.
    """
    for affected in vuln.get("affected") or []:
        specific = affected.get("database_specific") or {}
        value = specific.get("informational")
        if isinstance(value, str) and value.lower() in {
            "unmaintained",
            "yanked",
            "informational",
        }:
            return "informational"

    entries = vuln.get("severity") or []
    best = 0.0
    for entry in entries:
        numeric = entry.get("score")
        if isinstance(numeric, (int, float)):
            best = max(best, float(numeric))
            continue
        if isinstance(numeric, str) and numeric.replace(".", "", 1).isdigit():
            best = max(best, float(numeric))
    for floor, label in CVSS_BANDS:
        if best >= floor:
            return label
    return "unknown"


def analysis_of(vuln: dict) -> bool | None:
    """True if called, False if explicitly uncalled, None if no conclusion.

    The three states are distinct and the caller treats them differently. An
    absent entry is `None`, never `False`.
    """
    analysis = vuln.get("experimental_analysis")
    if not isinstance(analysis, dict):
        return None
    # The key is the advisory id the analysis applies to; take any verdict.
    for verdict in analysis.values():
        if isinstance(verdict, dict) and "called" in verdict:
            return bool(verdict["called"])
    return None


def evaluate(path: Path, threshold: str) -> tuple[int, list[str]]:
    """Return an exit code and the lines to print."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return 2, [f"error: could not read {path}: {error}"]

    floor = SEVERITIES.index(threshold)
    lines: list[str] = []
    failures: list[str] = []
    dismissed: list[str] = []
    informational: list[str] = []
    reported = 0

    for result in data.get("results") or []:
        for package in result.get("packages") or []:
            ident = package.get("package") or {}
            name = ident.get("name", "?")
            version = ident.get("version", "?")
            for vuln in package.get("vulnerabilities") or []:
                reported += 1
                vid = vuln.get("id", "?")
                severity = severity_of(vuln)
                called = analysis_of(vuln)
                label = f"{name} {version} {vid} severity={severity}"

                # An advisory class that is not a code weakness. Reported, never
                # failed: the fix is a dependency swap on its own schedule, not
                # an emergency, and a gate that treats it as one gets muted.
                if severity == "informational":
                    informational.append(f"  noted: {label}")
                    continue

                # `unknown` is not below the threshold. An unrated finding is
                # treated as at least the threshold, because the alternative is
                # that a database gap silently exempts it.
                if severity == "unknown":
                    pass
                elif SEVERITIES.index(severity) >= floor:
                    pass
                else:
                    continue

                if called is False:
                    dismissed.append(f"  dismissed: {label} (analysis: not called)")
                elif called is True:
                    failures.append(f"  FAIL: {label} (analysis: CALLED)")
                else:
                    failures.append(
                        f"  FAIL: {label} (analysis: none — treated as reachable)"
                    )

    if informational:
        lines.append("Advisories that are not code weaknesses (reported, not gated):")
        lines.extend(informational)
    if dismissed:
        lines.append("Findings dismissed on evidence:")
        lines.extend(dismissed)
    if failures:
        lines.append(f"Findings at or above '{threshold}' that reach the code path:")
        lines.extend(failures)

    summary = (
        f"osv-gate: {reported} finding(s) reported, "
        f"{len(failures)} at or above '{threshold}', "
        f"{len(dismissed)} dismissed, "
        f"{len(informational)} informational"
    )
    lines.append(summary)

    return (1 if failures else 0), lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Apply a severity policy to OSV-Scanner JSON output."
    )
    parser.add_argument("results", type=Path, help="the --format=json output file")
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="lowest severity that fails the gate (default: high)",
    )
    args = parser.parse_args(argv)

    code, lines = evaluate(args.results, args.fail_on)
    stream = sys.stderr if code else sys.stdout
    for line in lines:
        print(line, file=stream)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
