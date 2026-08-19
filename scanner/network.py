"""
NetGuard network assessment engine.

Use only against systems and networks that you own
or are explicitly authorized to assess.
"""

from __future__ import annotations

import socket
from typing import Any


# Common services.
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
}


# Exposure guidance.
SERVICE_RISK = {
    21: ("Medium", "FTP may transmit credentials insecurely."),
    22: ("Medium", "SSH is exposed; ensure strong authentication."),
    23: ("High", "Telnet is unencrypted and should normally be avoided."),
    25: ("Medium", "SMTP exposure should be restricted where possible."),
    139: ("High", "NetBIOS exposure can increase network attack surface."),
    445: ("High", "SMB exposure should be restricted to trusted networks."),
    3389: ("High", "RDP exposure should be restricted and protected."),
}


def validate_target(target: str) -> str:
    """Validate and normalize a hostname or IP address."""

    if not isinstance(target, str):
        raise ValueError("Target must be text.")

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    if len(target) > 253:
        raise ValueError("Target name is too long.")

    # Remove accidental URL schemes.
    if "://" in target:
        raise ValueError(
            "Enter a hostname or IP address, not a URL."
        )

    return target


def validate_ports(ports: list[int]) -> list[int]:
    """Validate a list of TCP ports."""

    if not ports:
        raise ValueError("At least one port is required.")

    validated = []

    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(
                f"Invalid port value: {port}"
            )

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Port {port} must be between 1 and 65535."
            )

        validated.append(port)

    # Remove duplicates while preserving order.
    return list(dict.fromkeys(validated))


def validate_timeout(timeout: float) -> float:
    """Keep connection timeouts within safe limits."""

    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        raise ValueError("Timeout must be a number.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    if timeout > 10:
        raise ValueError(
            "Timeout cannot be greater than 10 seconds."
        )

    return timeout


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address."""

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(
            f"Could not resolve target '{target}'."
        ) from exc


def assess_port(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> dict[str, Any]:
    """
    Assess one TCP port.

    This checks whether a TCP connection is accepted.
    An open port alone does NOT prove that a vulnerability exists.
    """

    target = validate_target(target)
    port = validate_ports([port])[0]
    timeout = validate_timeout(timeout)

    service = COMMON_SERVICES.get(
        port,
        "Unknown",
    )

    result: dict[str, Any] = {
        "target": target,
        "port": port,
        "service": service,
        "status": "closed",
        "risk": "Info",
        "finding": "",
        "action": "",
    }

    try:
        with socket.create_connection(
            (target, port),
            timeout=timeout,
        ):
            result["status"] = "open"

    except ConnectionRefusedError:
        return result

    except TimeoutError:
        result["status"] = "timeout"
        return result

    except socket.timeout:
        result["status"] = "timeout"
        return result

    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    # The port accepted a connection.
    # Apply exposure guidance, not a claim of vulnerability.
    risk, explanation = SERVICE_RISK.get(
        port,
        ("Low", "An accessible TCP service increases attack surface."),
    )

    result["risk"] = risk
    result["finding"] = (
        f"{service} is accepting TCP connections on port {port}. "
        f"{explanation}"
    )

    if port in SERVICE_RISK:
        result["action"] = (
            "Confirm the service is required. "
            "Restrict access to trusted networks where possible "
            "and keep the service securely configured."
        )
    else:
        result["action"] = (
            "Confirm the service is required and restrict "
            "unnecessary network exposure."
        )

    return result


def scan_host(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
) -> list[dict[str, Any]]:
    """
    Assess selected TCP ports on an authorized target.

    Returns only ports that are open or produced a meaningful
    assessment result.
    """

    target = validate_target(target)
    ports = validate_ports(ports)
    timeout = validate_timeout(timeout)

    # Resolve once before starting the assessment.
    resolve_target(target)

    findings = []

    for port in ports:
        result = assess_port(
            target,
            port,
            timeout,
        )

        if result["status"] != "closed":
            findings.append(result)

    return findings