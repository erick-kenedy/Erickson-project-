#!/usr/bin/env python3
"""
Simple entrypoint for Erickson-project scanner.
Run: python app.py
"""

from scanner import network, data


def main():
    url = "https://example.com"
    print("Fetching:", url)
    content = network.fetch_url(url)
    print("Content length:", len(content) if content else 0)
    data.save_data("output.json", {"url": url, "length": len(content) if content else 0})


if __name__ == "__main__":
    main()
