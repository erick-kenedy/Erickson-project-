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


AI_API_URL = os.getenv(
    "AI_API_URL",
    "",
)

AI_API_KEY = os.getenv(
    "AI_API_KEY",
    "",
)


def build_security_summary(
    findings: list[dict[str, Any]],
) -> str:
    """Create a safe summary for an AI model."""

    if not findings:
        return (
            "No security findings were detected. "
            "The assessment did not identify issues "
            "requiring immediate attention."
        )

    lines = []

    for finding in findings:
        lines.append(
            {
                "risk": finding.get("risk", "Info"),
                "type": finding.get(
                    "type",
                    "Security finding",
                ),
                "location": finding.get(
                    "location",
                    finding.get("path", ""),
                ),
                "finding": finding.get(
                    "finding",
                    "",
                ),
            }
        )

    return str(lines)


def ask_ai(
    findings: list[dict[str, Any]],
) -> str:
    """
    Ask the configured AI provider to explain findings.

    If AI is not configured, return a useful local message.
    """

    if not AI_API_URL or not AI_API_KEY:
        return (
            "AI assistance is not configured yet. "
            "Your security findings are still available "
            "through the NetGuard dashboard."
        )

    prompt = f"""
You are assisting with a defensive security assessment.

Explain the following findings in clear, simple language.

Focus on:
1. What the finding means.
2. Why it may matter.
3. Safe defensive remediation.
4. Which findings should be prioritized.

Do not provide instructions for attacking systems.

Findings:
{build_security_summary(findings)}
"""

    headers = {
        "Authorization": f"Bearer {AI_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "prompt": prompt,
        "max_tokens": 800,
    }

    try:
        response = requests.post(
            AI_API_URL,
            headers=headers,
            json=payload,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        # Provider response formats differ, so keep this
        # deliberately conservative.
        if isinstance(data, dict):

            if isinstance(
                data.get("text"),
                str,
            ):
                return data["text"]

            if isinstance(
                data.get("response"),
                str,
            ):
                return data["response"]

            if isinstance(
                data.get("content"),
                str,
            ):
                return data["content"]

        return (
            "The AI provider returned a response in an "
            "unsupported format."
        )

    except requests.RequestException:
        return (
            "The AI service could not be reached. "
            "Your scan results remain available locally."
        )
