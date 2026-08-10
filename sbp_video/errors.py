from __future__ import annotations


class VideoStudioError(Exception):
    """Base exception for the standalone video application."""


class ManifestValidationError(VideoStudioError, ValueError):
    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("invalid scene manifest: " + "; ".join(errors))


class AssetError(VideoStudioError):
    """Raised when an asset cannot be safely imported or resolved."""


class ToolUnavailableError(VideoStudioError):
    """Raised when an explicitly requested local render tool is unavailable."""


class RenderError(VideoStudioError):
    """Raised when a backend process fails."""
