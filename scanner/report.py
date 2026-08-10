import csv
import io
from typing import List, Dict


def generate_csv(findings: List[Dict]) -> str:
    """Return CSV text for a list of findings."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Risk", "Type", "Location", "Finding", "Action"])
    for f in findings:
        writer.writerow([
            f.get("risk", "Info"),
            f.get("type") or f.get("service") or "",
            f.get("path") or f.get("port", ""),
            f.get("finding", ""),
            f.get("action", ""),
        ])
    return output.getvalue()


def report_header(title: str) -> str:
    from datetime import datetime
    now = datetime.utcnow().isoformat() + "Z"
    header = f"{title}\nGenerated: {now}\n\n"
    return header
