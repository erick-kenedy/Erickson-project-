import requests
import socket
from typing import List, Dict


def fetch_url(url: str, timeout: int = 10) -> str | None:
    """Fetch the given URL and return text content. Returns None on error."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        # Simple error handling for the sample
        print(f"fetch_url error: {e}")
        return None


def _guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "tcp"


# Ports we consider high-risk if open (common sensitive services)
_HIGH_RISK_PORTS = {21, 22, 23, 25, 80, 139, 143, 443, 445, 3306, 3389, 5432, 5900}


def scan_host(target: str, ports: List[int], timeout: float = 0.5) -> List[Dict]:
    """Simple TCP port scanner.

    Attempts to connect to each port on the target. Returns a list of
    findings for open ports. This is intentionally conservative and
    synchronous — for large port lists consider an asynchronous approach.
    """
    findings = []

    for port in ports:
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                service = _guess_service(port)

                risk = "High" if port in _HIGH_RISK_PORTS else "Medium"

                findings.append({
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "finding": f"Accepted TCP connection on port {port} ({service}).",
                    "action": (
                        "Investigate the exposed service, ensure it is intended and properly secured, "
                        "and apply firewall rules or access controls if not needed."
                    ),
                })

        except (OSError, socket.timeout):
            # Port closed or filtered — not a finding
            continue

    return findings
