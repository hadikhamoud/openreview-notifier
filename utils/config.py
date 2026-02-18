from __future__ import annotations

import argparse
import json
import os
import tomllib
from pathlib import Path
from typing import Any


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if (not line) or line.startswith("#") or ("=" not in line):
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def load_toml_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"Invalid TOML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"Config at {path} must be a TOML table")
    return data


def config_section(config: dict[str, Any], name: str) -> dict[str, Any]:
    section = config.get(name, {})
    if section is None:
        return {}
    if isinstance(section, dict):
        return section
    raise SystemExit(f"Config section [{name}] must be a table")


def preparse_env_args(argv: list[str]) -> tuple[list[Path], bool]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--env-file", action="append", default=[])
    parser.add_argument("--no-default-env", action="store_true")
    args, _ = parser.parse_known_args(argv)
    env_paths = [Path(path) for path in args.env_file]
    return env_paths, args.no_default_env


def parse_header_pairs(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers:
        if ":" not in raw:
            raise SystemExit(
                f"Invalid --webhook-header value: {raw!r}. Use 'Name: Value'."
            )
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise SystemExit(f"Invalid --webhook-header value: {raw!r}")
        headers[name] = value
    return headers


def parse_json_headers(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"WEBHOOK_HEADERS_JSON must be valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("WEBHOOK_HEADERS_JSON must be a JSON object")
    return {str(key): str(value) for key, value in data.items()}
