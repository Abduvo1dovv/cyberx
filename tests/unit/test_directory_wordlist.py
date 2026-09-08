"""Directory wordlist: cap, depth 1, reject traversal and external URLs."""

from __future__ import annotations

from cyberx.recon.http.wordlist import (
    DEFAULT_DIRECTORY_LABELS,
    MAX_DIRECTORY_CANDIDATES,
    candidate_urls,
    normalize_label,
)


def test_wordlist_is_closed_and_capped() -> None:
    assert len(DEFAULT_DIRECTORY_LABELS) <= 50
    assert MAX_DIRECTORY_CANDIDATES == 50
    assert {"admin", "login", "robots.txt", "backup", "api", "uploads"} <= set(
        DEFAULT_DIRECTORY_LABELS
    )
    rows = candidate_urls("http://10.10.11.23/", limit=50)
    assert len(rows) <= 50
    assert all(path.count("/") == 1 for path, _url in rows)
    assert candidate_urls("http://10.10.11.23/", limit=200)  # still capped
    assert len(candidate_urls("http://10.10.11.23/", limit=200)) <= 50


def test_normalize_rejects_traversal_and_external() -> None:
    assert normalize_label("admin") == "admin"
    assert normalize_label("/robots.txt") == "robots.txt"
    assert normalize_label("  .git ") == ".git"
    for bad in (
        "../etc/passwd",
        "../../secret",
        "http://evil.example/x",
        "https://other.example",
        "javascript:alert(1)",
        "data:text/html,x",
        "admin/config",
        "api/v1/users",
        "//evil.example",
        "",
        "..",
        "/../",
    ):
        assert normalize_label(bad) is None


def test_candidates_stay_on_base_host() -> None:
    rows = candidate_urls("http://10.10.11.23/app", limit=8)
    urls = [u for _p, u in rows]
    assert all(u.startswith("http://10.10.11.23/") for u in urls)
    assert all("/app/" in u for u in urls)
    assert not any(".." in u for u in urls)
    assert not any("admin/config" in u for u in urls)
