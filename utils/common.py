from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_email_list(raw: str | None) -> list[str]:
    emails = parse_csv(raw)
    return [email for email in emails if "@" in email and "." in email]


def parse_string_list(raw: Any, label: str) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return parse_csv(raw)
    if isinstance(raw, list):
        values: list[str] = []
        for item in raw:
            text = str(item).strip()
            if text:
                values.append(text)
        return values
    raise SystemExit(f"{label} must be a string or list")


def parse_email_targets(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return parse_email_list(raw)
    if isinstance(raw, list):
        return parse_email_list(",".join(str(item) for item in raw))
    raise SystemExit("email.to must be a string or list")


def parse_bool(raw: Any, label: str, default: bool = False) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise SystemExit(f"{label} must be a boolean")


def parse_int(raw: Any, label: str, default: int) -> int:
    if raw is None:
        return default
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw.strip())
    raise SystemExit(f"{label} must be an integer")
