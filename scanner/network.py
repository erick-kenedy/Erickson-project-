"""
NetGuard network assessment engine.

Use only against systems and networks that you own
or are explicitly authorized to assess.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any


COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
}


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

    if "://" in target:
        raise ValueError(
            "Enter a hostname or IP address, not a URL."
        )

    # Reject whitespace inside the target.
    if any(character.isspace() for character in target):
        raise ValueError(
            "Target cannot contain spaces."
        )

    # Validate IP addresses when the target is an IP.
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Basic hostname validation.
    hostname = target.rstrip(".")

    if not hostname:
        raise ValueError("Invalid target.")

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                character.isalnum() or character == "-"
                for character in label
            )
        ):
            raise ValueError(
                "Invalid hostname."
            )

    return hostname


def validate_ports(ports: list[int]) -> list[int]:
    """Validate a list of TCP ports."""

    if not isinstance(ports, list):
        raise ValueError("Ports must be provided as a list.")

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

    return list(dict.fromkeys(validated))


def validate_timeout(timeout: float) -> float:
    """Keep connection timeouts within safe limits."""

    try:
        timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Timeout must be a number."
        ) from exc

    if timeout <= 0:
        raise ValueError(
            "Timeout must be greater than zero."
        )

    if timeout > 10:
        raise ValueError(
            "Timeout cannot be greater than 10 seconds."
        )

    return timeout


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address."""

    target = validate_target(target)

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

    An open port does not by itself prove a vulnerability.
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

    except (TimeoutError, socket.timeout):
        result["status"] = "timeout"
        return result

    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    risk, explanation = SERVICE_RISK.get(
        port,
        (
            "Low",
            "An accessible TCP service increases "
            "network attack surface.",
        ),
    )

    result["risk"] = risk

    result["finding"] = (
        f"{service} is accepting TCP connections "
        f"on port {port}. {explanation}"
    )

    if port in SERVICE_RISK:
        result["action"] = (
            "Confirm that the service is required. "
            "Restrict access to trusted networks where "
            "possible and keep the service securely configured."
        )
    else:
        result["action"] = (
            "Confirm that the service is required and "
            "restrict unnecessary network exposure."
        )

    return result


def scan_host(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
) -> list[dict[str, Any]]:
    """
    Assess selected TCP ports on an authorized target.

    Only meaningful results are returned.
    """

    target = validate_target(target)
    ports = validate_ports(ports)
    timeout = validate_timeout(timeout)

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