"""Report writers: console summary, CSV, and a self-contained HTML report."""
from __future__ import annotations

import csv
import html
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Dict, List

from .rules import Finding

COLORS = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#4b5563"}


def console_summary(findings: List[Finding], scores: Dict[str, int], total_accounts: int) -> str:
    by_sev = Counter(f.severity for f in findings)
    by_rule = Counter(f.rule for f in findings)
    lines = [
        f"Accounts reviewed : {total_accounts}",
        f"Findings          : {len(findings)}  "
        + "  ".join(f"{s}={by_sev.get(s, 0)}" for s in ("critical", "high", "medium", "low")),
        "",
        "By rule:",
    ]
    lines += [f"  {rule:<26} {n}" for rule, n in by_rule.most_common()]
    lines += ["", "Highest-risk accounts:"]
    lines += [f"  {user:<20} score {score}" for user, score in list(scores.items())[:5]]
    return "\n".join(lines)


def write_csv(findings: List[Finding], path: Path) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["severity", "rule", "account_id", "username", "detail", "recommendation"])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: getattr(f, k) for k in writer.fieldnames})


def write_html(findings: List[Finding], scores: Dict[str, int], total_accounts: int, as_of: date, path: Path) -> None:
    by_sev = Counter(f.severity for f in findings)
    cards = "".join(
        f'<div class="card"><div class="n" style="color:{COLORS[s]}">{by_sev.get(s, 0)}</div><div>{s.title()}</div></div>'
        for s in ("critical", "high", "medium", "low")
    )
    rows = "".join(
        "<tr>"
        f'<td><span class="sev" style="background:{COLORS[f.severity]}">{f.severity}</span></td>'
        f"<td>{html.escape(f.rule)}</td><td>{html.escape(f.username)}</td>"
        f"<td>{html.escape(f.detail)}</td><td>{html.escape(f.recommendation)}</td>"
        "</tr>"
        for f in findings
    )
    top = "".join(f"<li><b>{html.escape(u)}</b> ({s})</li>" for u, s in list(scores.items())[:5])
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Access Review Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;color:#111827;background:#f9fafb}}
h1{{margin:0 0 4px}} .muted{{color:#6b7280}}
.cards{{display:flex;gap:12px;margin:20px 0}} .card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:12px 20px;text-align:center}}
.n{{font-size:28px;font-weight:700}}
table{{border-collapse:collapse;width:100%;background:#fff}} th,td{{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top;font-size:14px}}
th{{background:#f3f4f6}} .sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:12px;text-transform:uppercase}}
</style></head><body>
<h1>Identity Access Review</h1>
<div class="muted">As of {as_of.isoformat()} &middot; {total_accounts} accounts reviewed &middot; {len(findings)} findings</div>
<div class="cards">{cards}</div>
<h3>Highest-risk accounts</h3><ol>{top}</ol>
<h3>Findings</h3>
<table><tr><th>Severity</th><th>Rule</th><th>Account</th><th>Detail</th><th>Recommendation</th></tr>{rows}</table>
</body></html>"""
    Path(path).write_text(doc)
