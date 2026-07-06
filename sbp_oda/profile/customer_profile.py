from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CustomerProfile:
    customer_id: str
    organisation_name: str
    owner_contact: str
