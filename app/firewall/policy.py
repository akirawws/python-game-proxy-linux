from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ActionType(str, Enum):
    DROP = "drop"
    RATE_LIMIT = "rate_limit"
    ALERT = "alert"
    BLOCK_SOURCE = "block_source"
    BLOCK_PORT = "block_port"


class PolicyProfile(str, Enum):
    WEB = "web"
    GAME = "game"
    CUSTOM = "custom"


@dataclass
class ServerPolicy:
    profile: PolicyProfile = PolicyProfile.CUSTOM
    allowed_actions: set[ActionType] = field(default_factory=lambda: set(ActionType))
    max_concurrent_blocks: int = 10
    cooldown_s: int = 0
    min_consecutive_violations: int = 1
    confirmation_window_s: int = 1
    whitelist: set[str] = field(default_factory=set)

    @classmethod
    def for_profile(cls, profile: PolicyProfile) -> "ServerPolicy":
        if profile == PolicyProfile.WEB:
            return cls(
                profile=PolicyProfile.WEB,
                allowed_actions={ActionType.RATE_LIMIT, ActionType.ALERT, ActionType.BLOCK_PORT},
                max_concurrent_blocks=10,
                cooldown_s=60,
            )
        if profile == PolicyProfile.GAME:
            return cls(
                profile=PolicyProfile.GAME,
                allowed_actions={ActionType.DROP, ActionType.RATE_LIMIT, ActionType.ALERT, ActionType.BLOCK_SOURCE},
                max_concurrent_blocks=20,
                cooldown_s=30,
            )
        return cls(
            profile=PolicyProfile.CUSTOM,
            allowed_actions=set(ActionType),
            max_concurrent_blocks=10,
            cooldown_s=0,
        )


__all__ = ["ActionType", "PolicyProfile", "ServerPolicy"]
