"""Deterministic HypothesisEngine. Hypotheses are not facts and never write claims."""

from __future__ import annotations

from cyberx.brain.types import HypothesisDelta
from cyberx.domain.models.findings import BrainContext

_TEMPLATES = {
    "host.unresolved": "hostname has not resolved to an address",
    "host.ports_unknown": "host ports have not been observed",
    "port.service_unknown": "open port has no service fingerprint",
    "service.http_unprobed": "http service has not been probed",
    "url.tech_unknown": "web surface technology is unknown",
    "domain.subdomains_unknown": "domain subdomains have not been enumerated",
    "service.directories_unknown": "http directories have not been enumerated",
    "endpoint.params_unknown": "endpoint parameters have not been observed",
}

_SIGNAL_TEMPLATES = {
    "auth_surface": "HTTP surface exposes an authentication boundary",
    "admin_surface": "HTTP surface exposes an administrative boundary",
    "tech_observed": "Technology fingerprint needs stronger evidence",
    "version_disclosure": "Exposed technology version needs confirmation",
    "unusual_service": "Unusual service fingerprint needs confirmation",
    "unusual_status": "Unusual HTTP behavior needs clarification",
    "unusual_redirect": "Redirect behavior needs in-scope confirmation",
}


class HypothesisEngine:
    def revise(self, ctx: BrainContext) -> list[HypothesisDelta]:
        existing = {row.statement for row in ctx.hypotheses}
        existing_core = {core_statement(row.statement) for row in ctx.hypotheses}
        deltas: list[HypothesisDelta] = []
        open_kinds = {gap.kind for gap in ctx.gaps}
        for gap in ctx.gaps:
            kind = gap.kind
            template = _TEMPLATES.get(kind, f"unresolved knowledge: {kind}")
            subject = gap.subject_key or gap.subject_id
            statement = f"{template} ({subject})" if subject else template
            if statement in existing or template in existing_core:
                continue
            deltas.append(
                HypothesisDelta(
                    op="create",
                    statement=statement[:500],
                    gap_kind=kind,
                    gap_id=gap.id,
                    subject_id=gap.subject_id,
                    confidence=0.3,
                    rationale=f"open gap {kind}",
                )
            )
            existing.add(statement)
            existing_core.add(template)
        for row in ctx.top_findings:
            signal = row.signal
            template = _SIGNAL_TEMPLATES.get(signal)
            if not template:
                continue
            fid = row.id
            statement = f"{template} ({fid})" if fid else template
            if statement in existing:
                continue
            deltas.append(
                HypothesisDelta(
                    op="create",
                    statement=statement[:500],
                    subject_id=row.asset_id,
                    confidence=0.3,
                    rationale=f"recon signal {signal}",
                )
            )
            existing.add(statement)
        for row in ctx.validation_candidates:
            if row.status != "supported":
                continue
            hid = row.hypothesis_id
            statement = ""
            for hyp in ctx.hypotheses:
                if hid and hyp.id == hid:
                    statement = hyp.statement
                    break
            if not hid and not statement:
                continue
            deltas.append(
                HypothesisDelta(
                    op="support",
                    statement=statement or "validation evidence supports hypothesis",
                    hypothesis_id=hid or None,
                    confidence=0.45,
                    rationale="validation candidate supported by evidence",
                )
            )
        for row in ctx.hypotheses:
            statement = row.statement
            gap_derived = any(template in statement for template in _TEMPLATES.values())
            if not gap_derived:
                continue
            kind_hit = False
            for kind, template in _TEMPLATES.items():
                if template in statement and kind in open_kinds:
                    kind_hit = True
                    break
            if not kind_hit and statement:
                deltas.append(
                    HypothesisDelta(
                        op="retire",
                        statement=statement,
                        hypothesis_id=row.id or None,
                        rationale="gap closed",
                    )
                )
        return deltas


def core_statement(statement: str) -> str:
    text = statement.strip()
    if " (" in text and text.endswith(")"):
        return text[: text.rfind(" (")].strip()
    return text
