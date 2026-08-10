import requests


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
