"""DNS and bounded subdomain reconnaissance. Parser remains in evidence.parsers."""

from cyberx.recon.dns.adapter import DnsAdapter, SubdomainAdapter
from cyberx.recon.dns.resolver import DnsAnswer, FixtureDnsResolver, UdpDnsResolver
from cyberx.recon.dns.wordlist import DEFAULT_LABELS, candidates_for

__all__ = [
    "DEFAULT_LABELS",
    "DnsAdapter",
    "DnsAnswer",
    "FixtureDnsResolver",
    "SubdomainAdapter",
    "UdpDnsResolver",
    "candidates_for",
]
