from pathlib import Path

from scanner.scan import (
    is_text_file,
    scan_directory,
)


def test_text_file_detection():
    assert is_text_file(
        Path("example.py")
    )

    assert is_text_file(
        Path("config.json")
    )


def test_binary_extension_is_not_text():
    assert not is_text_file(
        Path("photo.jpg")
    )


def test_scan_directory(tmp_path):
    test_file = tmp_path / "example.py"

    test_file.write_text(
        "print('hello')",
        encoding="utf-8",
    )

    findings = scan_directory(
        str(tmp_path),
        max_files=10,
    )

    assert isinstance(findings, list)


def test_detects_possible_secret(tmp_path):
    test_file = tmp_path / "config.py"

    test_file.write_text(
        "api_key = 'ABCDEFGHIJKLMNOP123456'",
        encoding="utf-8",
    )

    findings = scan_directory(
        str(tmp_path),
        max_files=10,
    )

    assert len(findings) >= 1
    assert findings[0]["type"] == "Possible API key"


def test_secret_value_is_not_returned(tmp_path):
    secret = "ABCDEFGHIJKLMNOP123456"

    test_file = tmp_path / "config.py"

    test_file.write_text(
        f"api_key = '{secret}'",
        encoding="utf-8",
    )

    findings = scan_directory(
        str(tmp_path),
        max_files=10,
    )

    assert findings

    finding_text = str(findings[0])

    assert secret not in finding_text
