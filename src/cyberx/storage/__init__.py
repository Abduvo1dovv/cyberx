"""Persistence adapters. Application code depends on ports, not sqlite3."""

from cyberx.storage.sqlite import SqliteStore

__all__ = ["SqliteStore"]
