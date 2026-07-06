from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LicenceBinding:
    deployment_id: str
    licence_id: str
    premises_id: str
    bound: bool = True
