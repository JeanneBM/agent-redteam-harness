from pathlib import Path

from redteam.cases import AttackCase, RequestSpec
from redteam.targets import TargetResponse

REPO = Path(__file__).resolve().parent.parent
SUITE = REPO / "cases" / "java-ci-triage"


def make_case(**overrides) -> AttackCase:
    base = dict(
        id="t-001",
        category="injection.direct",
        title="test",
        description="",
        severity="low",
        payload="[INFO] BUILD FAILURE\n[ERROR] error: release version 21 not supported\n",
        expect=({"type": "json_object"},),
        mapping={},
        request=RequestSpec(),
        path=None,
    )
    base.update(overrides)
    return AttackCase(**base)


def make_response(body: str = "{}", status: int = 200, error: str | None = None) -> TargetResponse:
    return TargetResponse(status, body, 1, error=error)
