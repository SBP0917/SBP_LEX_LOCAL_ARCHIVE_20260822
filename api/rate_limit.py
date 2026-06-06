from __future__ import annotations

from collections import deque
from time import monotonic
from threading import Lock


class RuntimeRateLimiter:
    def __init__(self, *, limit: int = 120, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> tuple[bool, dict[str, int | float]]:
        now = monotonic()
        with self._lock:
            events = self._events.setdefault(key, deque())
            while events and now - events[0] > self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False, {
                    "limit": self.limit,
                    "window_seconds": self.window_seconds,
                    "remaining": 0,
                }
            events.append(now)
            return True, {
                "limit": self.limit,
                "window_seconds": self.window_seconds,
                "remaining": self.limit - len(events),
            }


API_RATE_LIMITER = RuntimeRateLimiter()
