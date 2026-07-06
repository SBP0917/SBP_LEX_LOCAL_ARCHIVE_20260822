from __future__ import annotations

from enum import StrEnum


class DeploymentPackageClass(StrEnum):
    LOCAL_PREMISES = "LOCAL_PREMISES"
    TABLET_COMPANION = "TABLET_COMPANION"
    REMOTE_SUPPORT_PAIRED = "REMOTE_SUPPORT_PAIRED"
