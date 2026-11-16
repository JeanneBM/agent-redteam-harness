"""Command line: ``python -m redteam {run,list,validate}``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .cases import CaseError, load_suite
from .judge import Judge, OpenAiCompatibleJudge
from .report import write_reports
from .runner import EXIT_CODES, Policy, run_suite
from .simulated import SIMULATED_TARGETS
from .targets import HttpJsonTarget, Target, aks_remediation_target, java_ci_triage_target

TARGET_PRESETS = ("java-ci-triage", "aks-remediation", "http-json", *SIMULATED_TARGETS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redteam", description="Adversarial regression tests for LLM agents.")
    parser.add_argument("--version", action="version", version=f"redteam {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a suite against a target and write reports")
    run.add_argument("--suite", required=True, type=Path, help="directory of attack cases")
    run.add_argument("--target", required=True, choices=TARGET_PRESETS)
    run.add_argument("--base-url", help="agent base URL for the java-ci-triage and aks-remediation presets")
    run.add_argument(
        "--agent-token-env",
        default="AGENTIC_OPS_REMEDIATION_TOKEN",
        metavar="VAR",
        help="environment variable holding the X-Agent-Token for aks-remediation (default: %(default)s)",
    )
    run.add_argument("--url", help="full endpoint URL for the http-json target")
    run.add_argument(
        "--body-template",
        help='JSON body for http-json; the string "{{payload}}" is replaced by the attack payload',
    )
    run.add_argument("--header", action="append", default=[], metavar="NAME: VALUE", help="extra request header")
    run.add_argument("--timeout", type=float, default=30.0, help="request timeout in seconds")
    run.add_argument("--policy", type=Path, help="thresholds JSON (default: ASR 0%% everywhere)")
    run.add_argument("--judge", choices=("none", "openai"), default="none", help="judge for soft checks")
    run.add_argument("--output", required=True, type=Path, help="new directory for report.{json,md,html}")
    run.add_argument("--only", action="append", default=[], metavar="CASE_ID", help="run only these cases")

    lst = sub.add_parser("list", help="list the cases in a suite")
    lst.add_argument("--suite", required=True, type=Path)

    val = sub.add_parser("validate", help="validate a suite without running it")
    val.add_argument("--suite", required=True, type=Path)
    return parser


def make_target(args: argparse.Namespace) -> Target:
    headers = {}
    for raw in args.header:
        name, sep, value = raw.partition(":")
        if not sep:
            raise SystemExit(f"--header expects 'Name: value', got {raw!r}")
        headers[name.strip()] = value.strip()

    if args.target in SIMULATED_TARGETS:
        return SIMULATED_TARGETS[args.target]()
    if args.target == "java-ci-triage":
        if not args.base_url:
            raise SystemExit("--base-url is required for the java-ci-triage target")
        target = java_ci_triage_target(args.base_url, timeout_seconds=args.timeout)
        target.headers.update(headers)
        return target
    if args.target == "aks-remediation":
        if not args.base_url:
            raise SystemExit("--base-url is required for the aks-remediation target")
        token = os.environ.get(args.agent_token_env)
        if not token and "X-Agent-Token" not in headers:
            raise SystemExit(f"set {args.agent_token_env} or pass --header 'X-Agent-Token: ...'")
        target = aks_remediation_target(args.base_url, token, timeout_seconds=args.timeout)
        target.headers.update(headers)
        return target
    if not args.url or not args.body_template:
        raise SystemExit("--url and --body-template are required for the http-json target")
    try:
        template = json.loads(args.body_template)
    except json.JSONDecodeError as e:
        raise SystemExit(f"--body-template is not valid JSON: {e}") from e
    return HttpJsonTarget("http-json", args.url, template, timeout_seconds=args.timeout, headers=headers)


def make_judge(name: str) -> Judge | None:
    if name == "none":
        return None
    try:
        return OpenAiCompatibleJudge.from_env()
    except ValueError as e:
        raise SystemExit(str(e)) from e


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cases = load_suite(args.suite)
    except CaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.command == "validate":
        print(f"{len(cases)} valid case(s) in {args.suite}")
        return 0
    if args.command == "list":
        for case in cases:
            print(f"{case.id:40} {case.category:24} {case.severity:8} {case.title}")
        return 0

    if args.only:
        unknown = sorted(set(args.only) - {c.id for c in cases})
        if unknown:
            print(f"error: unknown case id(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c.id in args.only]

    policy = Policy.load(args.policy) if args.policy else Policy()
    target = make_target(args)
    judge = make_judge(args.judge)
    if args.output.exists():
        print(f"error: output directory already exists: {args.output}", file=sys.stderr)
        return 2

    def progress(result):
        print(f"{result.outcome:12} {result.case.id}")

    print(f"redteam {__version__}: {len(cases)} case(s) from {args.suite} against {target.name}")
    run = run_suite(cases, target, policy, judge, suite_name=str(args.suite), on_result=progress)
    paths = write_reports(run, args.output)
    counts = run.counts()
    print()
    for summary in run.categories():
        asr = "n/a" if summary.asr is None else f"{summary.asr * 100:.0f}%"
        flag = "  BREACHED" if summary.breached else ""
        print(f"{summary.category:24} ASR {asr:>4} (max {summary.max_asr * 100:.0f}%){flag}")
    print()
    print(
        f"verdict: {run.verdict()}  blocked={counts['BLOCKED']} succeeded={counts['SUCCEEDED']} "
        f"inconclusive={counts['INCONCLUSIVE']} error={counts['ERROR']}"
    )
    print(f"reports: {', '.join(str(p) for p in paths)}")
    return EXIT_CODES[run.verdict()]
