"""Write a run as report.json, report.md and report.html.

The output directory must not exist yet: reports are evidence and are never
overwritten. The HTML is self-contained (no scripts, no external assets) so it
opens from a file share on a locked-down host.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .runner import BLOCKED, ERROR, INCONCLUSIVE, SUCCEEDED, RunResult

OUTCOME_SYMBOL = {BLOCKED: "✅", SUCCEEDED: "❌", INCONCLUSIVE: "❔", ERROR: "⚠️"}


def write_reports(run: RunResult, output_dir: Path) -> list[Path]:
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError(f"Output directory already exists, choose a new one: {output_dir}")
    output_dir.mkdir(parents=True)
    paths = []
    for name, text in (
        ("report.json", json.dumps(run.to_dict(), indent=2, ensure_ascii=False) + "\n"),
        ("report.md", render_markdown(run)),
        ("report.html", render_html(run)),
    ):
        path = output_dir / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def render_markdown(run: RunResult) -> str:
    counts = run.counts()
    lines = [
        "# Agent red-team report",
        "",
        f"- **Verdict:** {run.verdict()}",
        f"- **Target:** `{run.target_name}`",
        f"- **Suite:** `{run.suite}`",
        f"- **Judge:** {run.judge_name or 'none (judge checks undecided)'}",
        f"- **Run:** {run.started_at} → {run.finished_at}",
        f"- **Cases:** {len(run.results)} — blocked {counts[BLOCKED]}, succeeded {counts[SUCCEEDED]}, "
        f"inconclusive {counts[INCONCLUSIVE]}, error {counts[ERROR]}",
        "",
        "## Attack success rate by category",
        "",
        "| Category | Blocked | Succeeded | Inconclusive | Error | ASR | Max ASR | Gate |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for c in run.categories():
        lines.append(
            f"| `{c.category}` | {c.blocked} | {c.succeeded} | {c.inconclusive} | {c.error} | "
            f"{_pct(c.asr)} | {_pct(c.max_asr)} | {'BREACHED' if c.breached else 'ok'} |"
        )
    lines += ["", "## Cases", ""]
    for r in run.results:
        lines.append(f"### {OUTCOME_SYMBOL[r.outcome]} `{r.case.id}` — {r.case.title}")
        lines.append("")
        mapping = ", ".join(f"{k}: {', '.join(v)}" for k, v in r.case.mapping.items()) or "—"
        lines.append(f"Category `{r.case.category}` · severity {r.case.severity} · {mapping}")
        lines.append("")
        lines.append(f"Outcome **{r.outcome}**, HTTP {r.response.status_code}, {r.response.elapsed_ms} ms")
        if r.response.error:
            lines.append(f"Transport error: `{r.response.error}`")
        lines.append("")
        for check in r.checks:
            mark = {True: "pass", False: "FAIL", None: "undecided"}[check.passed]
            lines.append(f"- `{check.type}` — {mark}: {check.detail}")
        lines.append("")
    return "\n".join(lines)


def render_html(run: RunResult) -> str:
    counts = run.counts()
    verdict = run.verdict()
    rows = "".join(
        f"<tr><td><code>{html.escape(c.category)}</code></td><td>{c.blocked}</td><td>{c.succeeded}</td>"
        f"<td>{c.inconclusive}</td><td>{c.error}</td><td>{_pct(c.asr)}</td><td>{_pct(c.max_asr)}</td>"
        f"<td class=\"{'breached' if c.breached else 'ok'}\">{'BREACHED' if c.breached else 'ok'}</td></tr>"
        for c in run.categories()
    )
    cases = []
    for r in run.results:
        checks = "".join(
            f"<li class=\"{ {True: 'pass', False: 'fail', None: 'undecided'}[c.passed] }\">"
            f"<code>{html.escape(c.type)}</code> — {html.escape(c.detail)}</li>"
            for c in r.checks
        )
        mapping = html.escape(", ".join(f"{k}: {', '.join(v)}" for k, v in r.case.mapping.items()) or "—")
        cases.append(
            f"<details class=\"{r.outcome.lower()}\"><summary>{OUTCOME_SYMBOL[r.outcome]} "
            f"<code>{html.escape(r.case.id)}</code> — {html.escape(r.case.title)} "
            f"<span class=\"meta\">{r.outcome} · HTTP {r.response.status_code} · {r.response.elapsed_ms} ms</span></summary>"
            f"<p>{html.escape(r.case.description)}</p>"
            f"<p class=\"meta\">Category <code>{html.escape(r.case.category)}</code> · severity {r.case.severity} · {mapping}</p>"
            + (f"<p class=\"fail\">Transport error: {html.escape(r.response.error)}</p>" if r.response.error else "")
            + f"<ul>{checks}</ul>"
            f"<h4>Payload</h4><pre>{html.escape(r.case.payload) or '(verbatim request body)'}</pre>"
            f"<h4>Response</h4><pre>{html.escape(r.response.body_text[:2000])}</pre>"
            "</details>"
        )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Agent red-team report — {html.escape(verdict)}</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
h1 .verdict{{padding:.1em .5em;border-radius:.3em;color:#fff;background:{ {'PASS': '#1a7f37', 'FAIL': '#cf222e', 'INCONCLUSIVE': '#9a6700'}[verdict] }}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ddd;padding:.3em .6em;text-align:right}}
td:first-child,th:first-child{{text-align:left}} .breached{{color:#cf222e;font-weight:bold}} .ok{{color:#1a7f37}}
details{{border:1px solid #ddd;border-radius:.4em;padding:.4em .8em;margin:.5em 0}} summary{{cursor:pointer}}
.meta{{color:#666;font-size:.9em}} pre{{background:#f6f8fa;padding:.6em;overflow:auto;white-space:pre-wrap}}
li.pass{{color:#1a7f37}} li.fail{{color:#cf222e}} li.undecided{{color:#9a6700}} .fail{{color:#cf222e}}
</style></head><body>
<h1>Agent red-team report <span class="verdict">{html.escape(verdict)}</span></h1>
<p>Target <code>{html.escape(run.target_name)}</code> · suite <code>{html.escape(run.suite)}</code> ·
judge {html.escape(run.judge_name or 'none')} · {html.escape(run.started_at)}</p>
<p>{len(run.results)} cases — blocked {counts[BLOCKED]}, succeeded {counts[SUCCEEDED]},
inconclusive {counts[INCONCLUSIVE]}, error {counts[ERROR]}</p>
<h2>Attack success rate by category</h2>
<table><thead><tr><th>Category</th><th>Blocked</th><th>Succeeded</th><th>Inconclusive</th><th>Error</th>
<th>ASR</th><th>Max ASR</th><th>Gate</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Cases</h2>
{''.join(cases)}
</body></html>
"""


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"
