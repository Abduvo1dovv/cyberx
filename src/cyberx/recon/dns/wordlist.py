"""Fixed v1 subdomain wordlist. Closed, ≤ 100 labels. No operator expansion."""

from __future__ import annotations

# SPEC §5.6.7: default list includes www,mail,dev,admin,api,staging,test,vpn
# and is capped at 100. Order is part of the coverage identity.
DEFAULT_LABELS: tuple[str, ...] = (
    "www",
    "mail",
    "dev",
    "admin",
    "api",
    "staging",
    "test",
    "vpn",
    "ftp",
    "ns1",
    "ns2",
    "webmail",
    "portal",
    "app",
    "blog",
    "shop",
    "cdn",
    "git",
    "ci",
    "db",
    "sql",
    "mysql",
    "smtp",
    "imap",
    "pop",
    "autodiscover",
    "remote",
    "secure",
    "intranet",
    "extranet",
    "beta",
    "qa",
    "uat",
    "demo",
    "docs",
    "status",
    "monitor",
    "grafana",
    "jenkins",
    "jira",
    "wiki",
    "help",
    "support",
    "sso",
    "auth",
    "login",
    "m",
    "mobile",
    "static",
    "assets",
    "img",
    "images",
    "files",
    "upload",
    "uploads",
    "backup",
    "old",
    "new",
    "stage",
    "prod",
    "internal",
    "corp",
    "office",
    "gw",
    "gateway",
    "proxy",
    "fw",
    "ntp",
    "time",
    "ldap",
    "ad",
    "dc",
    "exchange",
    "owa",
    "lync",
    "sip",
    "voip",
    "pbx",
    "crm",
    "erp",
    "shopify",
    "store",
    "pay",
    "billing",
    "invoice",
    "dev2",
    "test2",
    "api2",
    "www2",
    "origin",
    "edge",
)

assert len(DEFAULT_LABELS) <= 100
assert len(set(DEFAULT_LABELS)) == len(DEFAULT_LABELS)


def default_labels(*, limit: int = 100) -> tuple[str, ...]:
    cap = max(1, min(int(limit), 100))
    return DEFAULT_LABELS[:cap]


def candidates_for(domain: str, *, limit: int = 100) -> list[str]:
    zone = domain.strip().rstrip(".").lower()
    names: list[str] = []
    seen: set[str] = set()
    for label in default_labels(limit=limit):
        fqdn = f"{label}.{zone}"
        if fqdn in seen:
            continue
        seen.add(fqdn)
        names.append(fqdn)
        if len(names) >= limit:
            break
    return names
