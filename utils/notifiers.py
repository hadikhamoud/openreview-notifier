from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .common import utc_now


def send_sendgrid_email(
    api_key: str,
    from_email: str,
    to_emails: list[str],
    subject: str,
    body_text: str,
) -> tuple[bool, str]:
    payload = {
        "personalizations": [{"to": [{"email": email} for email in to_emails]}],
        "from": {"email": from_email},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body_text}],
    }
    request = Request(
        "https://api.sendgrid.com/v3/mail/send",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            return True, f"status={response.status}"
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return False, f"HTTP {exc.code}: {detail}"
    except URLError as exc:
        return False, f"Network error: {exc.reason}"


def notify_by_email(
    forum_id: str,
    note_id: str | None,
    changed: bool,
    events: list[str],
    overall_lines: list[str],
    sendgrid_api_key: str | None,
    from_email: str | None,
    to_emails: list[str],
) -> None:
    if not changed:
        return
    if not sendgrid_api_key or not from_email or not to_emails:
        print(f"[{utc_now()}] Email notification skipped (missing SendGrid config).")
        return

    lines = [
        f"Forum ID: {forum_id}",
        f"Note ID: {note_id or '-'}",
        f"Detected at: {utc_now()}",
        "",
        "Changes:",
    ]
    if events:
        lines.extend(f"- {event}" for event in events)
    else:
        lines.append("- Snapshot changed (non-review fields)")

    lines.append("")
    lines.append("Current reviewer overalls:")
    lines.extend(f"- {line}" for line in overall_lines)
    if not overall_lines:
        lines.append("- No reviews detected")

    subject = f"OpenReview change detected: forum {forum_id}"
    body = "\n".join(lines)
    ok, info = send_sendgrid_email(
        sendgrid_api_key, from_email, to_emails, subject, body
    )
    if ok:
        print(f"[{utc_now()}] Email sent to {', '.join(to_emails)} ({info})")
    else:
        print(f"[{utc_now()}] Email send failed: {info}")


def send_heartbeat_email(
    forum_id: str,
    note_id: str | None,
    digest: str,
    overall_lines: list[str],
    sendgrid_api_key: str | None,
    from_email: str | None,
    to_emails: list[str],
) -> None:
    if not sendgrid_api_key or not from_email or not to_emails:
        print(f"[{utc_now()}] Heartbeat email skipped (missing SendGrid config).")
        return

    lines = [
        f"Forum ID: {forum_id}",
        f"Note ID: {note_id or '-'}",
        f"Heartbeat at: {utc_now()}",
        f"Current snapshot hash: {digest}",
        "",
        "Current reviewer overalls:",
    ]
    lines.extend(f"- {line}" for line in overall_lines)
    if not overall_lines:
        lines.append("- No reviews detected")

    subject = f"OpenReview heartbeat: forum {forum_id}"
    body = "\n".join(lines)
    ok, info = send_sendgrid_email(
        sendgrid_api_key, from_email, to_emails, subject, body
    )
    if ok:
        print(f"[{utc_now()}] Heartbeat email sent to {', '.join(to_emails)} ({info})")
    else:
        print(f"[{utc_now()}] Heartbeat email failed: {info}")


def build_webhook_payload(
    event_type: str,
    forum_id: str,
    note_id: str | None,
    digest: str,
    score_events: list[str],
    overall_lines: list[str],
    has_change: bool,
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "detected_at": utc_now(),
        "forum_id": forum_id,
        "note_id": note_id,
        "snapshot_hash": digest,
        "has_change": has_change,
        "events": score_events,
        "review_overalls": overall_lines,
    }


def send_webhooks(
    targets: list[dict[str, Any]],
    payload: dict[str, Any],
    timeout_seconds: int,
    signing_secret: str | None,
) -> None:
    if not targets:
        print(f"[{utc_now()}] Webhook skipped (no webhook URL configured).")
        return

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    timeout = max(1, timeout_seconds)
    for target in targets:
        url = str(target.get("url", "")).strip()
        if not url:
            print(f"[{utc_now()}] Webhook skipped (empty URL entry).")
            continue

        raw_headers = target.get("headers") or {}
        if not isinstance(raw_headers, dict):
            print(f"[{utc_now()}] Webhook skipped for {url} (headers must be object).")
            continue
        headers = {
            "Content-Type": "application/json",
            **{str(key): str(value) for key, value in raw_headers.items()},
        }
        if signing_secret:
            signature = hmac.new(
                signing_secret.encode("utf-8"), payload_bytes, hashlib.sha256
            ).hexdigest()
            headers["X-OpenReview-Signature-SHA256"] = signature

        request = Request(
            url=url,
            data=payload_bytes,
            method="POST",
            headers=headers,
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                print(
                    f"[{utc_now()}] Webhook delivered to {url} status={response.status}"
                )
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            print(f"[{utc_now()}] Webhook failed to {url}: HTTP {exc.code}: {detail}")
        except URLError as exc:
            print(f"[{utc_now()}] Webhook failed to {url}: Network error: {exc.reason}")
