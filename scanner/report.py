"""
NetGuard report generation.

Provides CSV, JSON, HTML, and text reports from security findings.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from typing import Any


RISK_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


def report_timestamp() -> str:
    """Return an ISO-8601 UTC timestamp."""

    return datetime.now(
        timezone.utc
    ).isoformat()


def report_header(
    title: str = "NetGuard Security Assessment",
) -> str:
    """Create a readable text report header."""

    return (
        f"{title}\n"
        f"{'=' * len(title)}\n"
        f"Generated: {report_timestamp()}\n"
    )


def normalize_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """Convert a finding into a consistent report structure."""

    return {
        "risk": str(
            finding.get("risk", "Info")
        ),
        "type": str(
            finding.get("type")
            or finding.get("service")
            or "Security Finding"
        ),
        "target": str(
            finding.get("target", "")
        ),
        "port": finding.get(
            "port",
            "",
        ),
        "service": str(
            finding.get("service", "")
        ),
        "path": str(
            finding.get("path", "")
        ),
        "location": str(
            finding.get("location", "")
        ),
        "finding": str(
            finding.get("finding", "")
        ),
        "confidence": str(
            finding.get(
                "confidence",
                "Medium",
            )
        ),
        "action": str(
            finding.get("action", "")
        ),
    }


def sort_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Sort findings from highest to lowest risk."""

    return sorted(
        findings,
        key=lambda finding: RISK_ORDER.get(
            str(finding.get("risk", "Info")),
            99,
        ),
    )


def build_summary(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a summary of finding severity levels."""

    counts = Counter(
        str(finding.get("risk", "Info"))
        for finding in findings
    )

    return {
        "total": len(findings),
        "critical": counts.get("Critical", 0),
        "high": counts.get("High", 0),
        "medium": counts.get("Medium", 0),
        "low": counts.get("Low", 0),
        "info": counts.get("Info", 0),
    }


def generate_csv(
    findings: list[dict[str, Any]],
) -> str:
    """Generate a CSV report."""

    output = io.StringIO()

    fieldnames = [
        "risk",
        "type",
        "target",
        "port",
        "service",
        "path",
        "location",
        "finding",
        "confidence",
        "action",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )

    writer.writeheader()

    for finding in sort_findings(findings):
        writer.writerow(
            normalize_finding(finding)
        )

    return output.getvalue()


def generate_json(
    findings: list[dict[str, Any]],
) -> str:
    """Generate a structured JSON report."""

    summary = build_summary(findings)

    report = {
        "product": "NetGuard",
        "report_type": "Security Assessment",
        "generated_at": report_timestamp(),
        "summary": summary,
        "findings": [
            normalize_finding(finding)
            for finding in sort_findings(findings)
        ],
    }

    return json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
    )


def generate_text(
    findings: list[dict[str, Any]],
    title: str = "NetGuard Security Assessment",
) -> str:
    """Generate a readable plain-text report."""

    summary = build_summary(findings)

    lines = [
        report_header(title),
        "",
        "SUMMARY",
        "-------",
        f"Total findings: {summary['total']}",
        f"Critical: {summary['critical']}",
        f"High: {summary['high']}",
        f"Medium: {summary['medium']}",
        f"Low: {summary['low']}",
        f"Info: {summary['info']}",
        "",
        "FINDINGS",
        "--------",
    ]

    if not findings:
        lines.append(
            "No security findings were detected."
        )

    for index, finding in enumerate(
        sort_findings(findings),
        start=1,
    ):
        normalized = normalize_finding(
            finding
        )

        lines.extend(
            [
                "",
                f"Finding #{index}",
                f"Risk: {normalized['risk']}",
                f"Type: {normalized['type']}",
                f"Target: {normalized['target']}",
                f"Port: {normalized['port']}",
                f"Service: {normalized['service']}",
                f"Path: {normalized['path']}",
                f"Location: {normalized['location']}",
                f"Confidence: {normalized['confidence']}",
                f"Finding: {normalized['finding']}",
                (
                    "Recommended action: "
                    f"{normalized['action']}"
                ),
            ]
        )

    return "\n".join(lines)


def generate_html(
    findings: list[dict[str, Any]],
    title: str = "NetGuard Security Assessment",
) -> str:
    """Generate a standalone HTML report."""

    summary = build_summary(findings)

    rows = []

    for finding in sort_findings(findings):
        item = normalize_finding(finding)

        rows.append(
            f"""
            <tr>
                <td>{escape(str(item["risk"]))}</td>
                <td>{escape(str(item["type"]))}</td>
                <td>{escape(str(item["target"]))}</td>
                <td>{escape(str(item["port"]))}</td>
                <td>{escape(str(item["service"]))}</td>
                <td>{escape(str(item["location"]))}</td>
                <td>{escape(str(item["confidence"]))}</td>
                <td>{escape(str(item["finding"]))}</td>
                <td>{escape(str(item["action"]))}</td>
            </tr>
            """
        )

    if not rows:
        rows.append(
            """
            <tr>
                <td colspan="9">
                    No security findings were detected.
                </td>
            </tr>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>{escape(title)}</title>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 30px;
    line-height: 1.5;
}}

h1 {{
    margin-bottom: 5px;
}}

.meta {{
    margin-bottom: 25px;
}}

.summary {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(120px, 1fr));
    gap: 10px;
    margin-bottom: 25px;
}}

.summary-card {{
    border: 1px solid #ccc;
    padding: 12px;
    border-radius: 6px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}

th {{
    font-weight: bold;
}}

@media print {{
    body {{
        margin: 10px;
    }}

    table {{
        font-size: 10px;
    }}
}}
</style>
</head>

<body>

<h1>{escape(title)}</h1>

<div class="meta">
    <strong>Generated:</strong>
    {escape(report_timestamp())}
</div>

<div class="summary">

<div class="summary-card">
<strong>Total</strong><br>
{summary["total"]}
</div>

<div class="summary-card">
<strong>Critical</strong><br>
{summary["critical"]}
</div>

<div class="summary-card">
<strong>High</strong><br>
{summary["high"]}
</div>

<div class="summary-card">
<strong>Medium</strong><br>
{summary["medium"]}
</div>

<div class="summary-card">
<strong>Low</strong><br>
{summary["low"]}
</div>

<div class="summary-card">
<strong>Info</strong><br>
{summary["info"]}
</div>

</div>

<table>
<thead>
<tr>
    <th>Risk</th>
    <th>Type</th>
    <th>Target</th>
    <th>Port</th>
    <th>Service</th>
    <th>Location</th>
    <th>Confidence</th>
    <th>Finding</th>
    <th>Recommended Action</th>
</tr>
</thead>

<tbody>
{"".join(rows)}
</tbody>

</table>

</body>
</html>
"""


def generate_report(
    findings: list[dict[str, Any]],
    format_name: str = "text",
) -> str:
    """
    Generate a report using the requested format.

    Supported formats:
        text
        csv
        json
        html
    """

    format_name = format_name.lower().strip()

    if format_name == "csv":
        return generate_csv(findings)

    if format_name == "json":
        return generate_json(findings)

    if format_name == "html":
        return generate_html(findings)

    if format_name == "text":
        return generate_text(findings)

    raise ValueError(
        "Unsupported report format. "
        "Choose text, csv, json, or html."
    )