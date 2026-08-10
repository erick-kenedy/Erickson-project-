"""
NetGuard Security Scanner
Defensive network and data security assessment package.
"""

from .network import fetch_url
from .data import save_data

__all__ = ["fetch_url", "save_data"]
