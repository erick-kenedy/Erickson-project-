import os
import re
import stat


TEXT_EXTENSIONS = {
    ".txt",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".py",
    ".js",
    ".ts",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".php",
    ".html",
    ".css",
    ".sql",
    ".sh",
    ".bat",
    ".ps1",
    ".properties",
}


SECRET_PATTERNS = [
    (
        "Possible API key",
        re.compile(
            r'''(?i)\b(api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]'''
        ),
    ),
    (
        "Possible private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "Possible password",
        re.compile(
            r'''(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]'''
        ),
    ),
    (
        "Possible secret key",
        re.compile(
            r'''(?i)\b(secret[_-]?key|access[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{12,}['\"]'''
        ),
    ),
]


def check_permissions(path):
    findings = []

    if os.name == "nt":
        return findings

    try:
        mode = os.stat(path).st_mode

        if mode & stat.S_IROTH:
            findings.append({
                "path": path,
                "type": "World-readable file",
                "risk": "Medium",
                "finding": "The file is readable by other local users.",
                "action": "Restrict file permissions to the users or services that require access."
            })

        if mode & stat.S_IWOTH:
            findings.append({
                "path": path,
                "type": "World-writable file",
                "risk": "High",
                "finding": "Other local users can modify this file.",
                "action": "Remove unnecessary write permissions and review ownership."
            })

    except OSError:
        pass

    return findings


def scan_file(path):
    findings = []

    findings.extend(check_permissions(path))

    extension = os.path.splitext(path)[1].lower()

    if extension not in TEXT_EXTENSIONS:
        return findings

    try:
        if os.path.getsize(path) > 2_000_000:
            return findings

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            content = file.read()

    except (OSError, UnicodeError):
        return findings

    for label, pattern in SECRET_PATTERNS:

        if pattern.search(content):

            findings.append({
                "path": path,
                "type": label,
                "risk": "High",
                "finding": (
                    f"A pattern resembling {label.lower()} "
                    "was found. This may be a false positive."
                ),
                "action": (
                    "Remove exposed secrets, rotate affected credentials, "
                    "and store secrets in an appropriate secret-management system."
                )
            })

    return findings


def scan_directory(directory, max_files=1000):

    if not os.path.isdir(directory):
        raise ValueError("Directory does not exist.")

    findings = []
    checked = 0

    excluded = {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
    }

    for root, directories, files in os.walk(directory):

        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded
        ]

        for filename in files:

            if checked >= max_files:
                return findings

            path = os.path.join(root, filename)

            checked += 1

            findings.extend(scan_file(path))

    return findings
