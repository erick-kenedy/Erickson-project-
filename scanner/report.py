"""
NetGuard report generation.

Provides CSV, JSON, HTML, and text reports from security findings.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from html import escape
from typing import Any


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
        "risk": finding.get("risk", "Info"),
        "type": (
            finding.get("type")
            or finding.get("service")
            or "Security Finding"
        ),
        "target": finding.get("target", ""),
        "port": finding.get("port", ""),
        "service": finding.get("service", ""),
        "path": finding.get("path", ""),
        "location": finding.get("location", ""),
        "finding": finding.get("finding", ""),
        "confidence": finding.get(
            "confidence",
            "Medium",
        ),
        "action": finding.get("action", ""),
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

    for finding in findings:
        writer.writerow(
            normalize_finding(finding)
        )

    return output.getvalue()


def generate_json(
    findings: list[dict[str, Any]],
) -> str:
    """Generate a JSON report."""

    report = {
        "product": "NetGuard",
        "report_type": "Security Assessment",
        "generated_at": report_timestamp(),
        "finding_count": len(findings),
        "findings": [
            normalize_finding(finding)
            for finding in findings
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

    lines = [
        report_header(title),
        "",
        f"Total findings: {len(findings)}",
        "",
        "FINDINGS",
        "--------",
    ]

    if not findings:
        lines.append(
            "No security findings were detected."
        )

    for index, finding in enumerate(
        findings,
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
                f"Recommended action: {normalized['action']}",
            ]
        )

    return "\n".join(lines)


def generate_html(
    findings: list[dict[str, Any]],
    title: str = "NetGuard Security Assessment",
) -> str:
    """Generate a standalone HTML report."""

    rows = []

    for finding in findings:
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
    <br>
    <strong>Total findings:</strong>
    {len(findings)}
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