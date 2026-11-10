import time
from collections import deque
from typing import Optional

class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300, lockout_seconds: int = 900) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._attempts: dict[str, deque] = {}
        self._lockouts: dict[str, float] = {}

    def is_locked(self, key: str) -> Optional[float]:
        now = time.time()
        lockout_until = self._lockouts.get(key)
        if lockout_until and now < lockout_until:
            return lockout_until - now
        if lockout_until and now >= lockout_until:
            del self._lockouts[key]
        return None

    def record_failure(self, key: str) -> None:
        now = time.time()
        window_start = now - self.window_seconds
        attempts = self._attempts.setdefault(key, deque())
        while attempts and attempts[0] < window_start:
            attempts.popleft()
        attempts.append(now)
        if len(attempts) >= self.max_attempts:
            self._lockouts[key] = now + self.lockout_seconds

    def record_success(self, key: str) -> None:
        if key in self._attempts:
            del self._attempts[key]
        if key in self._lockouts:
            del self._lockouts[key]