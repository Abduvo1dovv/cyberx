"""Filesystem artifact store. DB holds metadata only — never raw blobs."""

from __future__ import annotations

from pathlib import Path

from cyberx.ports.execution import RawArtifact


class FileArtifactStore:
    def __init__(self, data_dir: str | Path) -> None:
        self._root = Path(data_dir)

    def mission_dir(self, mission_id: str) -> Path:
        path = self._root / "missions" / mission_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def put(self, artifact: RawArtifact) -> str:
        folder = self.mission_dir(artifact.mission_id) / "artifacts"
        folder.mkdir(parents=True, exist_ok=True)
        dest = folder / f"{artifact.artifact_id}.bin"
        dest.write_bytes(artifact.body or b"")
        return str(dest)
