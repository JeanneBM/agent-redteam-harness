"""Attack case loading and validation.

A suite is a directory. Each case is a subdirectory holding ``case.json`` and,
unless the request is given verbatim, a ``payload.txt`` with the adversarial
input. Keeping payloads in plain files makes multi-line injections readable and
diffable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CASE_FILE = "case.json"
PAYLOAD_FILE = "payload.txt"
ID_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CATEGORY_PATTERN = re.compile(r"^[a-z]+(\.[a-z]+)*$")
SEVERITIES = ("low", "medium", "high", "critical")


class CaseError(ValueError):
    """A case directory does not describe a valid attack case."""


@dataclass(frozen=True)
class RequestSpec:
    """How the payload is delivered. ``raw_body`` bypasses the target's template."""

    raw_body: str | None = None
    content_type: str | None = None


@dataclass(frozen=True)
class AttackCase:
    id: str
    category: str
    title: str
    description: str
    severity: str
    payload: str
    expect: tuple[dict[str, Any], ...]
    mapping: dict[str, list[str]] = field(default_factory=dict)
    request: RequestSpec = RequestSpec()
    path: Path | None = None


def load_suite(directory: Path) -> list[AttackCase]:
    """Load every case under ``directory``, sorted by id. Raises CaseError on the first invalid case."""
    directory = Path(directory)
    if not directory.is_dir():
        raise CaseError(f"Suite directory not found: {directory}")
    cases = []
    for case_dir in sorted(p for p in directory.iterdir() if p.is_dir()):
        if (case_dir / CASE_FILE).exists():
            cases.append(load_case(case_dir))
    if not cases:
        raise CaseError(f"No cases found under {directory}")
    ids = [c.id for c in cases]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise CaseError(f"Duplicate case ids: {', '.join(duplicates)}")
    return cases


def load_case(case_dir: Path) -> AttackCase:
    try:
        raw = json.loads((case_dir / CASE_FILE).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise CaseError(f"{case_dir / CASE_FILE}: invalid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise CaseError(f"{case_dir / CASE_FILE}: top level must be an object")

    case_id = _require_str(raw, "id", case_dir)
    if not ID_PATTERN.match(case_id):
        raise CaseError(f"{case_dir}: id must be kebab-case, got {case_id!r}")
    if case_id != case_dir.name:
        raise CaseError(f"{case_dir}: id {case_id!r} must equal the directory name")

    category = _require_str(raw, "category", case_dir)
    if not CATEGORY_PATTERN.match(category):
        raise CaseError(f"{case_dir}: category must look like 'family.kind', got {category!r}")

    severity = raw.get("severity", "medium")
    if severity not in SEVERITIES:
        raise CaseError(f"{case_dir}: severity must be one of {SEVERITIES}")

    expect = raw.get("expect")
    if not isinstance(expect, list) or not expect:
        raise CaseError(f"{case_dir}: expect must be a non-empty list of checks")
    for check in expect:
        if not isinstance(check, dict) or not isinstance(check.get("type"), str):
            raise CaseError(f"{case_dir}: every check needs a string 'type'")

    request_raw = raw.get("request", {})
    if not isinstance(request_raw, dict):
        raise CaseError(f"{case_dir}: request must be an object")
    request = RequestSpec(
        raw_body=request_raw.get("raw_body"),
        content_type=request_raw.get("content_type"),
    )

    payload_file = case_dir / PAYLOAD_FILE
    if payload_file.exists():
        payload = payload_file.read_text(encoding="utf-8")
    elif request.raw_body is not None:
        payload = ""
    else:
        raise CaseError(f"{case_dir}: missing {PAYLOAD_FILE} (or request.raw_body)")

    mapping = raw.get("mapping", {})
    if not isinstance(mapping, dict) or not all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(x, str) for x in v)
        for k, v in mapping.items()
    ):
        raise CaseError(f"{case_dir}: mapping must be an object of string lists")

    return AttackCase(
        id=case_id,
        category=category,
        title=_require_str(raw, "title", case_dir),
        description=raw.get("description", ""),
        severity=severity,
        payload=payload,
        expect=tuple(expect),
        mapping=mapping,
        request=request,
        path=case_dir,
    )


def _require_str(raw: dict[str, Any], key: str, case_dir: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CaseError(f"{case_dir}: '{key}' must be a non-empty string")
    return value
