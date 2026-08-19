"""
NetGuard AI service.

Provides AI-assisted explanations of security findings.

The API key is read from environment variables and is never
hard-coded into the source code.
"""

from __future__ import annotations

import os
from typing import Any

import requests


def get_ai_config() -> tuple[str, str]:
    """Read AI configuration from the environment."""
    return (
        os.getenv("AI_API_URL", "").strip(),
        os.getenv("AI_API_KEY", "").strip(),
    )


def build_security_summary(
    findings: list[dict[str, Any]],
) -> str:
    """
    Create a limited, safe summary for an AI model.

    Secret values are not included.
    """

    if not findings:
        return (
            "No security findings were detected. "
            "The assessment did not identify issues "
            "requiring immediate attention."
        )

    safe_findings = []

    for finding in findings[:50]:
        safe_findings.append(
            {
                "risk": str(
                    finding.get("risk", "Info")
                ),
                "type": str(
                    finding.get(
                        "type",
                        "Security finding",
                    )
                ),
                "location": str(
                    finding.get(
                        "location",
                        finding.get("path", ""),
                    )
                )[:300],
                "finding": str(
                    finding.get(
                        "finding",
                        "",
                    )
                )[:500],
            }
        )

    return str(safe_findings)


def ask_ai(
    findings: list[dict[str, Any]],
) -> str:
    """
    Ask the configured AI provider to explain findings.

    If AI is not configured or unavailable, return a
    useful local message instead of crashing the application.
    """

    api_url, api_key = get_ai_config()

    if not api_url or not api_key:
        return (
            "AI assistance is not configured yet. "
            "Your security findings are still available "
            "through the NetGuard dashboard."
        )

    summary = build_security_summary(findings)

    prompt = f"""
You are NetGuard's defensive security assistant.

Analyze these authorized security assessment findings.

For each important finding:
1. Explain what it means in simple language.
2. Explain why it matters.
3. Give safe defensive remediation.
4. Identify the priority: Critical, High, Medium, Low, or Info.

Do not provide instructions for attacking systems,
bypassing security controls, stealing credentials,
or gaining unauthorized access.

Keep the response concise and practical.

Findings:
{summary}
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "prompt": prompt,
        "max_tokens": 800,
    }

    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            return (
                "The AI provider returned an invalid response."
            )

        for key in ("text", "response", "content"):
            value = data.get(key)

            if isinstance(value, str) and value.strip():
                return value.strip()

        return (
            "The AI provider returned a response in an "
            "unsupported format."
        )

    except requests.Timeout:
        return (
            "The AI service timed out. "
            "Your scan results remain available."
        )

    except requests.RequestException:
        return (
            "The AI service could not be reached. "
            "Your scan results remain available."
        )

    except ValueError:
        return (
            "The AI provider returned invalid JSON. "
            "Your scan results remain available."
        )