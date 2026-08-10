from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import re
import shutil
from typing import Any, Mapping

from sbp_video.constants import ASSET_EXTENSIONS, ASSET_KINDS
from sbp_video.errors import AssetError


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def infer_asset_kind(path: str | Path) -> str:
    suffix = Path(path).suffix.lower()
    matches = [kind for kind, extensions in ASSET_EXTENSIONS.items() if suffix in extensions]
    if len(matches) != 1:
        raise AssetError(f"unsupported or ambiguous asset extension: {suffix or '<none>'}")
    return matches[0]


@dataclass(frozen=True)
class AssetRecord:
    id: str
    kind: str
    uri: str
    sha256: str
    filename: str
    media_type: str | None = None

    def to_manifest_entry(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


class AssetCache:
    """Content-addressed local asset cache; imports never mutate the source file."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def import_file(
        self,
        source: str | Path,
        *,
        kind: str | None = None,
        asset_id: str | None = None,
    ) -> AssetRecord:
        source_path = Path(source).expanduser().resolve()
        if not source_path.is_file():
            raise AssetError(f"asset source does not exist: {source_path}")
        resolved_kind = kind or infer_asset_kind(source_path)
        if resolved_kind not in ASSET_KINDS:
            raise AssetError(f"unsupported asset kind: {resolved_kind}")
        if source_path.suffix.lower() not in ASSET_EXTENSIONS[resolved_kind]:
            raise AssetError(f"extension {source_path.suffix.lower()} is not valid for {resolved_kind}")
        digest = _file_digest(source_path)
        target = self.root / digest[:2] / f"{digest}{source_path.suffix.lower()}"
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copy2(source_path, target)
        if _file_digest(target) != digest:
            raise AssetError("asset cache digest verification failed")
        chosen_id = asset_id or f"asset-{digest[:16]}"
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", chosen_id):
            raise AssetError(f"invalid asset id: {chosen_id}")
        return AssetRecord(
            id=chosen_id,
            kind=resolved_kind,
            uri=f"asset://{digest}/{source_path.name}",
            sha256=digest,
            filename=source_path.name,
        )

    def resolve(self, asset: Mapping[str, Any]) -> Path:
        uri = str(asset.get("uri", ""))
        digest = str(asset.get("sha256", ""))
        if not uri.startswith("asset://") or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AssetError("cache resolution requires asset:// URI and sha256")
        uri_digest = uri.removeprefix("asset://").split("/", 1)[0]
        if uri_digest != digest:
            raise AssetError("asset URI digest does not match manifest digest")
        candidates = list((self.root / digest[:2]).glob(f"{digest}.*"))
        if len(candidates) != 1 or not candidates[0].is_file():
            raise AssetError(f"asset is absent from cache: {digest}")
        if _file_digest(candidates[0]) != digest:
            raise AssetError(f"cached asset failed digest verification: {digest}")
        return candidates[0]


def resolve_manifest_assets(
    assets: list[dict[str, Any]],
    *,
    project_root: str | Path,
    cache: AssetCache | None = None,
) -> dict[str, Path]:
    root = Path(project_root).expanduser().resolve()
    resolved: dict[str, Path] = {}
    for asset in assets:
        uri = str(asset["uri"])
        if uri.startswith("asset://"):
            if cache is None:
                raise AssetError(f"asset cache is required for {asset['id']}")
            path = cache.resolve(asset)
        else:
            relative = Path(uri)
            if relative.is_absolute():
                raise AssetError(f"absolute asset URI is not portable: {asset['id']}")
            path = (root / relative).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise AssetError(f"asset URI escapes the project or is missing: {asset['id']}")
            expected = asset.get("sha256")
            if expected is not None and _file_digest(path) != expected:
                raise AssetError(f"asset digest mismatch: {asset['id']}")
        resolved[str(asset["id"])] = path
    return resolved
