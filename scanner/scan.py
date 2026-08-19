"""
NetGuard local data security scanner.

Scans authorized local files for potentially sensitive
information without exposing the detected secret itself.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


# Directories that normally should not be scanned.
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


# File extensions that are reasonable for text inspection.
TEXT_EXTENSIONS = {
    ".txt",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".swift",
    ".kt",
    ".kts",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".sql",
    ".sh",
    ".bash",
    ".zsh",
    ".html",
    ".css",
    ".md",
}


# Patterns identify possible secrets.
# The actual matched value is NEVER returned to the UI.
SECRET_PATTERNS = [
    (
        "Possible API key",
        re.compile(
            r"(?i)\b(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"
        ),
    ),
    (
        "Possible password",
        re.compile(
            r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}"
        ),
    ),
    (
        "Possible secret key",
        re.compile(
            r"(?i)\b(secret[_-]?key|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"
        ),
    ),
    (
        "Possible private key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
        ),
    ),
]


def validate_directory(directory: str) -> Path:
    """Validate the directory supplied by the user."""

    if not isinstance(directory, str):
        raise ValueError("Directory must be text.")

    directory = directory.strip()

    if not directory:
        raise ValueError("Directory cannot be empty.")

    path = Path(directory).expanduser()

    if not path.exists():
        raise ValueError(
            f"Directory does not exist: {directory}"
        )

    if not path.is_dir():
        raise ValueError(
            f"Path is not a directory: {directory}"
        )

    return path.resolve()


def is_excluded(path: Path, root: Path) -> bool:
    """Return True when a path is inside an excluded directory."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        return True

    return any(
        part in DEFAULT_EXCLUDED_DIRS
        for part in relative.parts
    )


def is_text_file(path: Path) -> bool:
    """Determine whether a file is suitable for text scanning."""

    return (
        path.suffix.lower() in TEXT_EXTENSIONS
        or path.name.startswith(".env")
    )


def safe_read_text(
    path: Path,
    max_bytes: int,
) -> str | None:
    """
    Read a text file safely.

    Returns None when the file cannot reasonably be read.
    """

    try:
        if path.stat().st_size > max_bytes:
            return None

        return path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

    except (OSError, UnicodeError):
        return None


def line_number(text: str, position: int) -> int:
    """Return the 1-based line number for a text position."""

    return text.count("\n", 0, position) + 1


def create_finding(
    path: Path,
    root: Path,
    finding_type: str,
    line: int | None = None,
    confidence: str = "Medium",
) -> dict[str, Any]:
    """Create a safe finding without including secret values."""

   