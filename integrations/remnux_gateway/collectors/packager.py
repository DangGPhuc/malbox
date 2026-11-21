from __future__ import annotations

import hashlib
import json
import os
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..contracts.schemas import ArtifactMetadata, EvidenceManifest


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def package_evidence_bundle(
    source_dir: Path,
    output_archive: Path,
    manifest: EvidenceManifest,
) -> Tuple[bool, Optional[str]]:
    """
    Packages the raw evidence directory into a standardized tar.gz archive.
    Includes manifest.json at the root of the archive.
    """
    try:
        output_archive.parent.mkdir(parents=True, exist_ok=True)
        manifest_file = source_dir / "manifest.json"

        # Scan artifacts in source_dir and record in manifest
        artifacts_meta: List[ArtifactMetadata] = []
        for p in source_dir.rglob("*"):
            if p.is_file() and p.name != "manifest.json":
                rel = p.relative_to(source_dir).as_posix()
                sha = compute_file_sha256(p)
                size = p.stat().st_size
                cat = "dynamic" if "dynamic" in rel else ("static" if "static" in rel else "artifact")
                artifacts_meta.append(ArtifactMetadata(
                    name=p.name,
                    path=rel,
                    sha256=sha,
                    size_bytes=size,
                    category=cat,
                ))

        manifest.artifacts = artifacts_meta
        manifest_file.write_text(json.dumps(manifest.model_dump(), indent=2), encoding="utf-8")

        # Create tar.gz without absolute paths or symlinks
        with tarfile.open(output_archive, "w:gz") as tar:
            for p in source_dir.rglob("*"):
                if p.is_file():
                    arcname = p.relative_to(source_dir).as_posix()
                    tar.add(p, arcname=arcname, recursive=False)

        return True, None
    except Exception as e:
        return False, str(e)


def validate_and_extract_evidence_bundle(
    archive_path: Path,
    destination_dir: Path,
    max_total_bytes: int = 150_000_000,
) -> Tuple[bool, Optional[EvidenceManifest], Optional[str]]:
    """
    Safely validates and extracts an evidence archive:
    1. Rejects path traversal (..), absolute paths, and symlinks.
    2. Enforces maximum uncompressed extraction size limit.
    3. Reads and validates manifest.json.
    4. Validates artifact hashes against manifest.
    """
    if not archive_path.is_file():
        return False, None, f"Archive file does not exist: {archive_path}"

    destination_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            # 1. Pre-inspection pass for safety
            for member in tar.getmembers():
                # Check for path traversal or absolute paths
                if member.name.startswith("/") or ".." in member.name:
                    return False, None, f"Illegal path traversal detected in archive entry: {member.name}"
                # Reject symlinks and hardlinks to prevent host escape
                if member.issym() or member.islnk():
                    return False, None, f"Symlinks/hardlinks not permitted in evidence bundle: {member.name}"

                total_bytes += member.size
                if total_bytes > max_total_bytes:
                    return False, None, f"Archive exceeds maximum allowed uncompressed size ({max_total_bytes} bytes)"

            # 2. Safe extraction pass
            try:
                tar.extractall(path=destination_dir, filter="data")
            except TypeError:
                tar.extractall(path=destination_dir)

        # 3. Validate manifest
        manifest_path = destination_dir / "manifest.json"
        if not manifest_path.is_file():
            return False, None, "Evidence bundle missing mandatory manifest.json"

        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = EvidenceManifest.model_validate(manifest_data)

        # 4. Verify artifact hashes
        for art in manifest.artifacts:
            art_file = destination_dir / art.path
            if art_file.is_file():
                actual_sha = compute_file_sha256(art_file)
                if actual_sha.lower() != art.sha256.lower():
                    return False, manifest, f"Artifact hash mismatch for {art.path}: expected {art.sha256}, got {actual_sha}"

        return True, manifest, None
    except Exception as e:
        return False, None, f"Archive validation error: {str(e)}"
