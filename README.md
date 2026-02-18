# openreview-parser

Tiny OpenReview monitor that polls a forum and reports score changes.

## 1) Prerequisite

- Install `uv`: https://docs.astral.sh/uv/

## 2) Configure

```bash
cp .env.example .env
cp monitor.toml.example monitor.toml
```

Put your OpenReview and webhook settings in `monitor.toml`.
If `openreview.email` or `openreview.password` is missing, the script prompts for them.

Getting OpenReview IDs:

- `forum_id`: open a paper page and copy the value after `id=` in `https://openreview.net/forum?id=...`
- `note_id`: optional; copy from `noteId=` when present in the URL
- you can set `openreview.url` instead, and the script will parse `forum_id`/`note_id`

Per-webhook headers:

- set global headers in `[webhook.headers]`
- add endpoint-specific headers in each `[[webhook.targets]]` under `[webhook.targets.headers]`

## 3) Run

```bash
uv run monitor_openreview.py
```

Optional overrides:

- custom config file: `uv run monitor_openreview.py --config monitor.prod.toml`
- extra env files: `uv run monitor_openreview.py --env-file prod.env`
- disable default `.env`: `uv run monitor_openreview.py --no-default-env`

