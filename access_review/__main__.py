"""Command-line entry point: python -m access_review --data sample_data"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .models import Policy, load_accounts, load_employees
from .report import console_summary, write_csv, write_html
from .rules import Context, risk_scores, run_rules


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Automated identity access review.")
    parser.add_argument("--data", type=Path, default=Path("sample_data"),
                        help="Folder with hr_roster.csv, identities.csv, entitlements.csv, policy.json")
    parser.add_argument("--out", type=Path, default=Path("output"), help="Folder for findings.csv and report.html")
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today(),
                        help="Review date (YYYY-MM-DD); defaults to today")
    parser.add_argument("--fail-on", choices=["critical", "high", "never"], default="critical",
                        help="Exit non-zero when findings at this severity or above exist (for CI pipelines)")
    args = parser.parse_args(argv)

    employees = load_employees(args.data / "hr_roster.csv")
    accounts = load_accounts(args.data / "identities.csv", args.data / "entitlements.csv")
    policy = Policy.load(args.data / "policy.json")

    findings = run_rules(Context(accounts, employees, policy, args.as_of))
    scores = risk_scores(findings)

    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(findings, args.out / "findings.csv")
    write_html(findings, scores, len(accounts), args.as_of, args.out / "report.html")

    print(console_summary(findings, scores, len(accounts)))
    print(f"\nReports written to {args.out}/findings.csv and {args.out}/report.html")

    blocking = {"critical": {"critical"}, "high": {"critical", "high"}, "never": set()}[args.fail_on]
    return 1 if any(f.severity in blocking for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
