"""Local-first, non-authoritative scene construction and video rendering."""

from sbp_video.editor import ProjectEditor
from sbp_video.manifest import SceneManifest, validate_manifest

__all__ = ["ProjectEditor", "SceneManifest", "validate_manifest"]
__version__ = "0.1.0"
