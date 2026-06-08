from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


class CandidateQueue:
    def __init__(self, candidates: list[Dict[str, Any]]) -> None:
        self._queue = [deepcopy(candidate) for candidate in candidates]
        self._index = 0

    def has_next(self) -> bool:
        return self._index < len(self._queue)

    def next(self) -> Dict[str, Any] | None:
        if not self.has_next():
            return None
        candidate = deepcopy(self._queue[self._index])
        self._index += 1
        return candidate

    def remaining_count(self) -> int:
        return max(0, len(self._queue) - self._index)
