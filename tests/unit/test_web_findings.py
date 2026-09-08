"""Recon-only web findings. No vulnerability claims."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture

from cyberx.domain.enums import FindingKind
from cyberx.domain.ids import PREFIX_MISSION, new_id
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.world.model import InMemoryWorldModel


def test_auth_and_interesting_path_findings() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    artifact = artifact_from_fixture(
        "endpoint/forms.html",
        adapter_name="endpoint_adapter",
        media_type="text/html",
        source_locator="http://10.10.11.23/",
        mission_id=world.mission_id,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)
    kinds = {f.kind for f in world.get_findings()}
    assert FindingKind.AUTH_SURFACE in kinds
    assert FindingKind.INTERESTING_PATH in kinds
    blob = " ".join(f.title.lower() + f.summary.lower() for f in world.get_findings())
    assert "sql injection" not in blob
    assert "xss" not in blob
    assert "rce" not in blob
    assert "auth bypass" not in blob


def test_directory_paths_appear_as_urls() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    artifact = artifact_from_fixture(
        "endpoint/index_of.html",
        adapter_name="endpoint_adapter",
        media_type="text/html",
        source_locator="http://10.10.11.23/backup",
        mission_id=world.mission_id,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)
    paths = {u.path for u in world.get_web_surfaces()}
    assert any("dump.sql" in p or p == "/backup" for p in paths)
