"""Pure parsers. No network, no process execution, no World Model apply."""

from cyberx.evidence.parsers.directory import DirectoryParser
from cyberx.evidence.parsers.dns import DnsParser
from cyberx.evidence.parsers.endpoint import EndpointParser
from cyberx.evidence.parsers.http_probe import HttpProbeParser
from cyberx.evidence.parsers.nmap_xml import NmapXmlParser
from cyberx.evidence.parsers.stub import StubParser
from cyberx.evidence.parsers.tech import TechnologyParser

V1_PARSERS = (
    NmapXmlParser(),
    HttpProbeParser(),
    DnsParser(),
    DirectoryParser(),
    TechnologyParser(),
    EndpointParser(),
    StubParser(),
)

__all__ = [
    "DirectoryParser",
    "DnsParser",
    "EndpointParser",
    "HttpProbeParser",
    "NmapXmlParser",
    "StubParser",
    "TechnologyParser",
    "V1_PARSERS",
]
