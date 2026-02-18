from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import utc_now


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[{utc_now()}] Warning: state file is invalid JSON, starting fresh.")
        return {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
