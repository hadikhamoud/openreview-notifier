from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import openreview

from .common import utc_now


def parse_ids_from_url(url: str) -> tuple[str | None, str | None]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    forum_id = query.get("id", [None])[0]
    note_id = query.get("noteId", [None])[0]

    if (not forum_id) and query.get("redirect"):
        redirect = unquote(query["redirect"][0])
        redirect_query = parse_qs(urlparse(redirect).query)
        forum_id = redirect_query.get("id", [None])[0]
        note_id = redirect_query.get("noteId", [None])[0]

    return forum_id, note_id


def normalize_note(note: Any) -> dict[str, Any]:
    invitations = getattr(note, "invitations", None)
    if invitations is None:
        invitation_single = getattr(note, "invitation", None)
        invitations = [invitation_single] if invitation_single else []
    return {
        "id": getattr(note, "id", None),
        "forum": getattr(note, "forum", None),
        "replyto": getattr(note, "replyto", None),
        "number": getattr(note, "number", None),
        "cdate": getattr(note, "cdate", None),
        "tcdate": getattr(note, "tcdate", None),
        "tmdate": getattr(note, "tmdate", None),
        "signatures": sorted(getattr(note, "signatures", []) or []),
        "writers": sorted(getattr(note, "writers", []) or []),
        "readers": sorted(getattr(note, "readers", []) or []),
        "nonreaders": sorted(getattr(note, "nonreaders", []) or []),
        "invitation": getattr(note, "invitation", None),
        "invitations": sorted(invitations or []),
        "content": getattr(note, "content", {}) or {},
    }


def stable_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def extract_content_value(raw: Any) -> Any:
    if isinstance(raw, dict) and "value" in raw:
        return raw["value"]
    return raw


def pick_first(content: dict[str, Any], keys: list[str]) -> str:
    lowered = {key.lower(): key for key in content.keys()}
    for key in keys:
        actual = lowered.get(key.lower())
        if actual is None:
            continue
        value = extract_content_value(content.get(actual))
        if value is None:
            continue
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        if isinstance(value, (dict, tuple, set)):
            return json.dumps(value, sort_keys=True)
        return str(value)
    return "-"


def is_review_note(note: dict[str, Any]) -> bool:
    invitation_parts = []
    if note.get("invitation"):
        invitation_parts.append(str(note.get("invitation")))
    invitation_parts.extend(str(x) for x in (note.get("invitations") or []))
    invitation = " ".join(invitation_parts).lower()

    if any(
        marker in invitation
        for marker in [
            "official_review",
            "/review",
            "metareview",
            "meta_review",
            "meta-review",
            "public_comment",
            "ethics_review",
        ]
    ):
        return True

    content = note.get("content") or {}
    return (
        pick_first(
            content,
            [
                "rating",
                "overall_score",
                "overall recommendation",
                "recommendation",
                "confidence",
            ],
        )
        != "-"
    )


def print_note_type_debug(snapshot: dict[str, Any]) -> None:
    notes = snapshot["forum_notes"]
    print(f"[{utc_now()}] Note type debug ({len(notes)} notes):")
    for idx, note in enumerate(notes, start=1):
        invitations = ", ".join(note.get("invitations") or []) or (
            note.get("invitation") or "-"
        )
        content_keys = list((note.get("content") or {}).keys())
        preview = ", ".join(content_keys[:8])
        print(
            f"[{utc_now()}] Note {idx}: id={note.get('id') or '-'} "
            f"invitations={invitations} content_keys=[{preview}]"
        )


def print_review_assessments(snapshot: dict[str, Any]) -> None:
    review_notes = [note for note in snapshot["forum_notes"] if is_review_note(note)]
    print(f"[{utc_now()}] Reviews detected: {len(review_notes)}")
    if not review_notes:
        return

    review_notes.sort(
        key=lambda note: (
            note.get("number") if note.get("number") is not None else 10**9,
            note.get("id") or "",
        )
    )

    for idx, review in enumerate(review_notes, start=1):
        content = review.get("content") or {}
        rating = pick_first(
            content,
            [
                "rating",
                "overall_score",
                "overall recommendation",
                "recommendation",
                "overall_assessment",
                "overall assessment",
                "score",
            ],
        )
        confidence = pick_first(content, ["confidence", "reviewer confidence"])
        novelty = pick_first(content, ["novelty", "excitement"])
        soundness = pick_first(content, ["soundness", "technical quality"])
        signature = ", ".join(review.get("signatures") or []) or "-"
        print(
            f"[{utc_now()}] Review {idx}: note={review.get('id') or '-'} "
            f"signature={signature} rating={rating} confidence={confidence} "
            f"novelty={novelty} soundness={soundness}"
        )


def build_review_scores(snapshot: dict[str, Any]) -> dict[str, dict[str, str]]:
    scores: dict[str, dict[str, str]] = {}
    review_notes = [note for note in snapshot["forum_notes"] if is_review_note(note)]
    for review in review_notes:
        note_id = review.get("id")
        if not note_id:
            continue
        content = review.get("content") or {}
        signatures = review.get("signatures") or []
        reviewer = str(signatures[0]) if signatures else note_id
        scores[note_id] = {
            "reviewer": reviewer,
            "rating": pick_first(
                content,
                [
                    "rating",
                    "overall_score",
                    "overall recommendation",
                    "recommendation",
                    "overall_assessment",
                    "overall assessment",
                    "score",
                ],
            ),
            "confidence": pick_first(content, ["confidence", "reviewer confidence"]),
            "novelty": pick_first(content, ["novelty", "excitement"]),
            "soundness": pick_first(content, ["soundness", "technical quality"]),
        }
    return scores


def build_overall_lines(scores: dict[str, dict[str, str]]) -> list[str]:
    overall_lines = []
    for idx, note_id in enumerate(sorted(scores.keys()), start=1):
        score = scores[note_id]
        overall_lines.append(f"reviewer {idx} overall {score.get('rating', '-')}")
    return overall_lines


def print_review_score_changes(
    previous: dict[str, dict[str, str]], current: dict[str, dict[str, str]]
) -> list[str]:
    events: list[str] = []
    prev_ids = set(previous.keys())
    curr_ids = set(current.keys())

    for note_id in sorted(curr_ids - prev_ids):
        score = current[note_id]
        event = (
            f"REVIEW ADDED note={note_id} rating={score['rating']} "
            f"confidence={score['confidence']} novelty={score['novelty']} "
            f"soundness={score['soundness']}"
        )
        events.append(event)
        print(f"[{utc_now()}] {event}")

    for note_id in sorted(prev_ids - curr_ids):
        event = f"REVIEW REMOVED note={note_id}"
        events.append(event)
        print(f"[{utc_now()}] {event}")

    for note_id in sorted(curr_ids & prev_ids):
        before = previous[note_id]
        after = current[note_id]
        changed_fields = ["rating", "confidence", "novelty", "soundness"]
        deltas = [
            f"{field}:{before[field]}->{after[field]}"
            for field in changed_fields
            if before[field] != after[field]
        ]
        if not deltas:
            continue
        event = f"REVIEW SCORE CHANGED note={note_id} {' '.join(deltas)}"
        events.append(event)
        print(f"[{utc_now()}] {event}")

    return events


def print_poll_details(snapshot: dict[str, Any]) -> None:
    notes = snapshot["forum_notes"]
    last_modified = (
        max(
            (note.get("tmdate") or note.get("tcdate") or note.get("cdate") or 0)
            for note in notes
        )
        if notes
        else 0
    )
    print(
        f"[{utc_now()}] Poll details: total_notes={len(notes)} "
        f"last_modified_ms={last_modified} forum_id={snapshot['forum_id']} "
        f"note_id={snapshot.get('note_id') or '-'}"
    )


def fetch_forum_snapshot(
    client: openreview.api.OpenReviewClient,
    forum_id: str,
    note_id: str | None,
) -> dict[str, Any]:
    notes = client.get_all_notes(forum=forum_id)
    normalized = [normalize_note(note) for note in notes]
    normalized.sort(
        key=lambda note: (
            note["number"] if note["number"] is not None else 10**9,
            note["id"] or "",
        )
    )

    root = None
    if note_id:
        try:
            root = normalize_note(client.get_note(note_id))
        except Exception:
            root = None

    return {
        "forum_id": forum_id,
        "note_id": note_id,
        "root_note": root,
        "forum_notes": normalized,
    }
