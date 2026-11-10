from __future__ import annotations

from typing import Optional

from app.storage.repository import Repository

SENSITIVE_FIELDS = {"password", "token", "secret", "csrf", "cookie", "session", "hash"}

class AuditService:
    def __init__(self, repository: Repository) -> None:
        self.repo = repository

    def log(
        self,
        action: str,
        details: str = "",
        user_id: Optional[int] = None,
        result: str = "ok",
    ) -> int:
        safe_details = self._mask(details)
        return self.repo.append_audit(action, safe_details, user_id, result)

    def _mask(self, text: str) -> str:
        lower = text.lower()
        for field in SENSITIVE_FIELDS:
            if field in lower:
                return "***"
        return text