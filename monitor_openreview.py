#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["openreview-py>=1.45.0"]
# ///

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

import openreview

from utils.common import (
    parse_bool,
    parse_csv,
    parse_email_list,
    parse_email_targets,
    parse_int,
    parse_string_list,
    utc_now,
)
from utils.config import (
    config_section,
    load_dotenv,
    load_toml_config,
    parse_header_pairs,
    parse_json_headers,
    preparse_env_args,
)
from utils.notifiers import (
    build_webhook_payload,
    notify_by_email,
    send_heartbeat_email,
    send_webhooks,
)
from utils.openreview_utils import (
    build_overall_lines,
    build_review_scores,
    fetch_forum_snapshot,
    parse_ids_from_url,
    print_note_type_debug,
    print_poll_details,
    print_review_assessments,
    print_review_score_changes,
    stable_hash,
)
from utils.state import load_state, save_state


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Poll OpenReview forum/note and detect changes."
    )

    parser.add_argument(
        "--config",
        default="monitor.toml",
        help="Path to TOML config file",
    )

    parser.add_argument(
        "--env-file",
        action="append",
        default=[],
        help="Load KEY=VALUE pairs from this file (can be repeated).",
    )
    parser.add_argument(
        "--no-default-env",
        action="store_true",
        help="Do not auto-load .env from current directory.",
    )

    parser.add_argument("--url", help="OpenReview forum URL or login redirect URL")
    parser.add_argument("--forum-id", help="Forum ID (if --url is not provided)")
    parser.add_argument("--note-id", help="Optional note ID")
    parser.add_argument(
        "--interval-minutes", type=int, help="Polling interval in minutes"
    )
    parser.add_argument("--state-file", help="Where to persist the last hash")
    parser.add_argument("--api-baseurl")
    parser.add_argument("--email")
    parser.add_argument("--password")

    parser.add_argument(
        "--print-reviews",
        action="store_true",
        help="Print extracted reviewer assessments each poll",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print extra poll details",
    )
    parser.add_argument(
        "--debug-note-types",
        action="store_true",
        help="Print invitation/content keys for all notes",
    )

    parser.add_argument(
        "--email-on-change",
        action="store_true",
        help="Send SendGrid email when snapshot/review changes",
    )
    parser.add_argument(
        "--heartbeat-email-minutes",
        type=int,
        help="Send heartbeat email every N minutes regardless of changes",
    )

    parser.add_argument(
        "--webhook-on-change",
        action="store_true",
        help="Send webhook when snapshot/review changes",
    )
    parser.add_argument(
        "--test-webhook-now",
        action="store_true",
        help="Send one webhook immediately after first poll",
    )
    parser.add_argument(
        "--webhook-url",
        action="append",
        help="Webhook URL (can be repeated)",
    )
    parser.add_argument(
        "--webhook-header",
        action="append",
        help="Webhook header as 'Name: Value' (can be repeated)",
    )
    parser.add_argument(
        "--webhook-timeout-seconds",
        type=int,
        help="Webhook request timeout in seconds",
    )
    parser.add_argument(
        "--webhook-signing-secret",
        help="Optional HMAC SHA256 signing secret",
    )
    return parser


def main() -> None:
    env_paths, no_default_env = preparse_env_args(sys.argv[1:])
    if not no_default_env:
        load_dotenv(Path(".env"))
    for env_path in env_paths:
        load_dotenv(env_path)

    parser = build_parser()
    args = parser.parse_args()

    config = load_toml_config(Path(args.config))
    openreview_cfg = config_section(config, "openreview")
    email_cfg = config_section(config, "email")
    webhook_cfg = config_section(config, "webhook")
    debug_cfg = config_section(config, "debug")

    forum_id = args.forum_id or openreview_cfg.get("forum_id")
    note_id = args.note_id or openreview_cfg.get("note_id")
    openreview_url = args.url or openreview_cfg.get("url")
    if openreview_url:
        parsed_forum_id, parsed_note_id = parse_ids_from_url(str(openreview_url))
        forum_id = forum_id or parsed_forum_id
        note_id = note_id or parsed_note_id
    if not forum_id:
        forum_id = input("OpenReview forum id: ").strip()
    if not forum_id:
        raise SystemExit("Forum id is required.")

    api_baseurl = (
        args.api_baseurl
        or openreview_cfg.get("api_baseurl")
        or "https://api2.openreview.net"
    )
    interval_minutes = max(
        1,
        args.interval_minutes
        if args.interval_minutes is not None
        else parse_int(
            openreview_cfg.get("interval_minutes"), "openreview.interval_minutes", 10
        ),
    )
    state_file = (
        args.state_file
        or openreview_cfg.get("state_file")
        or ".openreview_watch_state.json"
    )

    email = (
        args.email
        or openreview_cfg.get("email")
        or os.getenv("OPENREVIEW_EMAIL")
        or input("OpenReview email: ").strip()
    )
    password = (
        args.password
        or openreview_cfg.get("password")
        or os.getenv("OPENREVIEW_PASSWORD")
        or getpass.getpass("OpenReview password: ")
    )
    if not email or not password:
        raise SystemExit("Email/password are required.")

    email_on_change = args.email_on_change or parse_bool(
        email_cfg.get("on_change"), "email.on_change", False
    )
    heartbeat_minutes = max(
        0,
        args.heartbeat_email_minutes
        if args.heartbeat_email_minutes is not None
        else parse_int(
            email_cfg.get("heartbeat_minutes"), "email.heartbeat_minutes", 0
        ),
    )
    sendgrid_api_key = email_cfg.get("sendgrid_api_key") or os.getenv(
        "SENDGRID_API_KEY"
    )
    alert_email_from = email_cfg.get("from") or os.getenv("ALERT_EMAIL_FROM")
    alert_email_to = parse_email_targets(email_cfg.get("to")) or parse_email_list(
        os.getenv("ALERT_EMAIL_TO")
    )

    webhook_on_change = args.webhook_on_change or parse_bool(
        webhook_cfg.get("on_change"), "webhook.on_change", False
    )
    test_webhook_now = args.test_webhook_now or parse_bool(
        webhook_cfg.get("test_now"), "webhook.test_now", False
    )
    config_webhook_urls = parse_string_list(webhook_cfg.get("urls"), "webhook.urls")
    env_webhook_urls = parse_csv(os.getenv("WEBHOOK_URLS"))
    cli_headers = parse_header_pairs(args.webhook_header or [])
    env_headers = parse_json_headers(os.getenv("WEBHOOK_HEADERS_JSON"))

    raw_global_headers = webhook_cfg.get("headers", {})
    if raw_global_headers is None:
        raw_global_headers = {}
    if not isinstance(raw_global_headers, dict):
        raise SystemExit("[webhook.headers] must be a TOML table")
    global_headers = {
        **env_headers,
        **{str(key): str(value) for key, value in raw_global_headers.items()},
        **cli_headers,
    }

    raw_targets = webhook_cfg.get("targets", [])
    if raw_targets is None:
        raw_targets = []
    if not isinstance(raw_targets, list):
        raise SystemExit("webhook.targets must be an array of tables")

    webhook_targets: list[dict[str, object]] = []
    for target in raw_targets:
        if not isinstance(target, dict):
            raise SystemExit("Each item in webhook.targets must be a table")
        target_url = str(target.get("url", "")).strip()
        if not target_url:
            continue
        target_headers_raw = target.get("headers", {})
        if target_headers_raw is None:
            target_headers_raw = {}
        if not isinstance(target_headers_raw, dict):
            raise SystemExit("Each webhook target headers must be a table")
        target_headers = {
            **global_headers,
            **{str(key): str(value) for key, value in target_headers_raw.items()},
        }
        webhook_targets.append({"url": target_url, "headers": target_headers})

    if not webhook_targets:
        fallback_urls = args.webhook_url or config_webhook_urls or env_webhook_urls
        webhook_targets = [
            {"url": str(url), "headers": global_headers}
            for url in fallback_urls
            if str(url).strip()
        ]
    webhook_timeout_seconds = max(
        1,
        args.webhook_timeout_seconds
        if args.webhook_timeout_seconds is not None
        else parse_int(
            webhook_cfg.get("timeout_seconds") or os.getenv("WEBHOOK_TIMEOUT_SECONDS"),
            "webhook.timeout_seconds",
            10,
        ),
    )
    webhook_signing_secret = (
        args.webhook_signing_secret
        or webhook_cfg.get("signing_secret")
        or os.getenv("WEBHOOK_SIGNING_SECRET")
    )

    print_reviews = args.print_reviews or parse_bool(
        debug_cfg.get("print_reviews"), "debug.print_reviews", False
    )
    verbose = args.verbose or parse_bool(
        debug_cfg.get("verbose"), "debug.verbose", False
    )
    debug_note_types = args.debug_note_types or parse_bool(
        debug_cfg.get("debug_note_types"), "debug.debug_note_types", False
    )

    interval_seconds = interval_minutes * 60
    state_path = Path(state_file)
    state = load_state(state_path)

    print(f"[{utc_now()}] Logging in to {api_baseurl} as {email}")
    client = openreview.api.OpenReviewClient(
        baseurl=api_baseurl,
        username=email,
        password=password,
    )

    print(
        f"[{utc_now()}] Watching forum={forum_id}"
        + (f" note={note_id}" if note_id else "")
        + f" every {interval_minutes} minute(s)."
    )

    test_webhook_sent = False
    last_heartbeat_at = 0.0

    while True:
        try:
            snapshot = fetch_forum_snapshot(client, forum_id, note_id)
            digest = stable_hash(snapshot)
            previous_digest = state.get("hash")
            previous_scores = state.get("review_scores") or {}
            current_scores = build_review_scores(snapshot)
            overall_lines = build_overall_lines(current_scores)

            is_baseline = previous_digest is None
            has_change = (not is_baseline) and (previous_digest != digest)
            if is_baseline:
                print(f"[{utc_now()}] Baseline captured.")
            elif has_change:
                print(f"[{utc_now()}] CHANGE DETECTED")
            else:
                print(f"[{utc_now()}] No change")

            score_events = print_review_score_changes(previous_scores, current_scores)

            if test_webhook_now and (not test_webhook_sent):
                payload = build_webhook_payload(
                    event_type="test",
                    forum_id=forum_id,
                    note_id=note_id,
                    digest=digest,
                    score_events=["TEST WEBHOOK. Monitoring is active."],
                    overall_lines=overall_lines,
                    has_change=False,
                )
                send_webhooks(
                    targets=webhook_targets,
                    payload=payload,
                    timeout_seconds=webhook_timeout_seconds,
                    signing_secret=webhook_signing_secret,
                )
                test_webhook_sent = True

            if webhook_on_change and has_change:
                payload = build_webhook_payload(
                    event_type="change",
                    forum_id=forum_id,
                    note_id=note_id,
                    digest=digest,
                    score_events=score_events,
                    overall_lines=overall_lines,
                    has_change=True,
                )
                send_webhooks(
                    targets=webhook_targets,
                    payload=payload,
                    timeout_seconds=webhook_timeout_seconds,
                    signing_secret=webhook_signing_secret,
                )

            if email_on_change:
                notify_by_email(
                    forum_id=forum_id,
                    note_id=note_id,
                    changed=has_change,
                    events=score_events,
                    overall_lines=overall_lines,
                    sendgrid_api_key=sendgrid_api_key,
                    from_email=alert_email_from,
                    to_emails=alert_email_to,
                )

            if heartbeat_minutes > 0:
                now_ts = time.time()
                if (last_heartbeat_at == 0.0) or (
                    (now_ts - last_heartbeat_at) >= heartbeat_minutes * 60
                ):
                    send_heartbeat_email(
                        forum_id=forum_id,
                        note_id=note_id,
                        digest=digest,
                        overall_lines=overall_lines,
                        sendgrid_api_key=sendgrid_api_key,
                        from_email=alert_email_from,
                        to_emails=alert_email_to,
                    )
                    last_heartbeat_at = now_ts

            if verbose:
                print_poll_details(snapshot)
            if debug_note_types:
                print_note_type_debug(snapshot)
            if print_reviews:
                print_review_assessments(snapshot)

            state = {
                "forum_id": forum_id,
                "note_id": note_id,
                "hash": digest,
                "review_scores": current_scores,
                "last_checked_at": utc_now(),
            }
            save_state(state_path, state)
        except Exception as exc:
            print(f"[{utc_now()}] Polling error: {exc}")

        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
