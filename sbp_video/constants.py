from __future__ import annotations

SCHEMA_VERSION = "sbp-video-scene/v1"
APP_NAME = "SBP Video Studio"
APP_VERSION = "0.1.0"
RUNTIME_AUTHORITY = "NONE"

OBJECT_TYPES = frozenset({"primitive", "mesh", "curve", "text", "empty"})
PRIMITIVE_TYPES = frozenset({"cube", "plane", "sphere", "cylinder", "cone", "torus"})
LIGHT_TYPES = frozenset({"point", "sun", "spot", "area"})
EFFECT_TYPES = frozenset({"particles", "glow", "fog", "trail"})
OVERLAY_TYPES = frozenset({"text", "hud", "data"})
ASSET_KINDS = frozenset({"model", "image", "audio", "font", "video", "data"})
OUTPUT_FORMATS = frozenset({"mp4", "webm", "mov", "png_sequence", "exr_sequence"})
BLENDER_ENGINES = frozenset({"BLENDER_EEVEE_NEXT", "BLENDER_EEVEE", "CYCLES", "BLENDER_WORKBENCH"})

ASSET_EXTENSIONS = {
    "model": frozenset({".blend", ".fbx", ".glb", ".gltf", ".obj", ".stl", ".ply"}),
    "image": frozenset({".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".exr", ".hdr"}),
    "audio": frozenset({".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac"}),
    "font": frozenset({".ttf", ".otf", ".woff", ".woff2"}),
    "video": frozenset({".mp4", ".webm", ".mov", ".mkv", ".avi"}),
    "data": frozenset({".json", ".csv", ".tsv", ".txt"}),
}

ID_PATTERN = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
