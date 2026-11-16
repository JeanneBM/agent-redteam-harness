"""Targets: how an attack payload reaches the agent under test.

A target turns an :class:`AttackCase` into one request and returns a
:class:`TargetResponse`. Network targets use only the standard library so the
harness runs on an air-gapped host next to the agent.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from .cases import AttackCase

MAX_BODY_BYTES = 1_000_000
PAYLOAD_MARKER = "{{payload}}"


@dataclass(frozen=True)
class TargetResponse:
    status_code: int | None
    body_text: str
    elapsed_ms: int
    error: str | None = None

    @property
    def json(self) -> dict[str, Any] | None:
        """The body as a JSON object, or None if it is not one."""
        try:
            parsed = json.loads(self.body_text)
        except (json.JSONDecodeError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None


class Target(Protocol):
    name: str

    def send(self, case: AttackCase) -> TargetResponse: ...


def render_body(template: Any, payload: str) -> Any:
    """Substitute the payload marker anywhere in a JSON-like template.

    A string equal to the marker becomes the whole payload; a string containing it
    gets the payload spliced in. Substitution happens on the parsed structure, so
    the payload is always JSON-encoded correctly whatever it contains.
    """
    if isinstance(template, str):
        if template == PAYLOAD_MARKER:
            return payload
        return template.replace(PAYLOAD_MARKER, payload)
    if isinstance(template, list):
        return [render_body(item, payload) for item in template]
    if isinstance(template, dict):
        return {key: render_body(value, payload) for key, value in template.items()}
    return template


class HttpJsonTarget:
    """POST a JSON body built from a template to one URL.

    With ``body_template=None`` the payload itself is the request body, verbatim.
    That is the mode for suites whose payloads are whole JSON documents.
    """

    def __init__(
        self,
        name: str,
        url: str,
        body_template: Any,
        timeout_seconds: float = 30.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.url = url
        self.body_template = body_template
        self.timeout_seconds = timeout_seconds
        self.headers = dict(headers or {})

    def send(self, case: AttackCase) -> TargetResponse:
        if case.request.raw_body is not None:
            data = case.request.raw_body.encode("utf-8")
        elif self.body_template is None:
            data = case.payload.encode("utf-8")
        else:
            data = json.dumps(render_body(self.body_template, case.payload)).encode("utf-8")
        headers = {"Content-Type": case.request.content_type or "application/json", **self.headers}
        for name, value in case.request.headers.items():
            if value is None:
                headers.pop(name, None)
            else:
                headers[name] = value
        request = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
                return TargetResponse(response.status, body, _elapsed(started))
        except urllib.error.HTTPError as e:
            body = e.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
            return TargetResponse(e.code, body, _elapsed(started))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return TargetResponse(None, "", _elapsed(started), error=f"{type(e).__name__}: {e}")


def java_ci_triage_target(base_url: str, timeout_seconds: float = 30.0) -> HttpJsonTarget:
    """Preset for JeanneBM/java-ci-triage-agent: ``POST /triage {"log": ...}``."""
    return HttpJsonTarget(
        name="java-ci-triage",
        url=base_url.rstrip("/") + "/triage",
        body_template={"log": PAYLOAD_MARKER},
        timeout_seconds=timeout_seconds,
    )


def aks_remediation_target(
    base_url: str, agent_token: str | None, timeout_seconds: float = 30.0
) -> HttpJsonTarget:
    """Preset for the remediation workload of JeanneBM/azure-kubernetes-agentic-ops-eval.

    ``POST /internal/v1/remediate`` with the handoff document as the body and the
    shared agent token in ``X-Agent-Token``. Payloads are whole JSON documents.
    """
    headers = {"X-Agent-Token": agent_token} if agent_token else {}
    return HttpJsonTarget(
        name="aks-remediation",
        url=base_url.rstrip("/") + "/internal/v1/remediate",
        body_template=None,
        timeout_seconds=timeout_seconds,
        headers=headers,
    )


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
