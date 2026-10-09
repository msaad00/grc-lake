"""Self-contained, frozen HTML evidence reports.

Reports render saved data directly. The API-backed console remains available
through ``serve``; an exported file requires neither that API nor JavaScript.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from security_lakehouse.assessment import build_current_posture
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.evidence_provenance import contains_synthetic_evidence
from security_lakehouse.generations import generation_reader
from security_lakehouse.io import read_json, read_jsonl
from security_lakehouse.readiness_coverage import readiness_coverage


def render_dashboard(lake_dir: str | Path, out_path: str | Path) -> Path:
    """Write a complete offline report without depending on a console build."""
    app_data = _load_app_data(Path(lake_dir))
    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_fallback_html(app_data), encoding="utf-8")
    return output


@generation_reader
def _load_app_data(lake: Path) -> dict[str, Any]:
    # First-boot tolerance: when the container mounts an empty lake, every
    # gold/silver file is absent. Return an empty payload rather than
    # crashing — the React app renders fine against empty arrays and the
    # operator pipes evidence in afterwards.
    dashboard_path = lake / "gold" / "dashboard_data.json"
    dashboard = read_json(dashboard_path) if dashboard_path.is_file() else {}
    posture_path = lake / "gold" / "current_posture.json"
    silver_path = lake / "silver" / "normalized_events.jsonl"
    if posture_path.is_file():
        posture = read_json(posture_path)
    elif silver_path.is_file():
        posture = build_current_posture(lake)
    else:
        posture = {
            "schema_version": "trustops.assessment.v1",
            "assessment_type": "current_posture",
            "evaluated_at": None,
            "posture": {
                "score": 0,
                "state": "attention_required",
                "framework_count": 0,
                "control_count": 0,
                "asset_count": 0,
                "open_violation_count": 0,
                "critical_violation_count": 0,
                "high_violation_count": 0,
                "stale_control_count": 0,
            },
            "frameworks": [],
            "violations": [],
            "top_risk_assets": [],
            "stale_controls": [],
            "assessment_hash": "",
        }
    events = read_jsonl(silver_path) if silver_path.is_file() else []
    return {
        "synthetic_fixture": contains_synthetic_evidence(lake, events),
        "framework_catalog_counts": dict(Counter(str(row["framework"]) for row in load_control_catalog().values())),
        "generated_at": dashboard.get("generated_at"),
        "metrics": dashboard.get("metrics", {}),
        "controls": dashboard.get("control_posture", []),
        "control_tests": dashboard.get("control_tests", []),
        "assets": dashboard.get("asset_risk", []),
        "events": events,
        "posture": posture,
        "sources": dashboard.get("source_mix", []),
        "routes": dashboard.get("backend_routes", []),
        "stages": dashboard.get("pipeline_stages", []),
    }


def _text(value: object) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def _table(headers: list[str], rows: list[list[object]], *, caption: str, empty: str) -> str:
    if not rows:
        return f'<p class="muted">{_text(empty)}</p>'
    head = "".join(f'<th scope="col">{_text(label)}</th>' for label in headers)
    body = "".join("<tr>" + "".join(f"<td>{_text(value)}</td>" for value in row) + "</tr>" for row in rows)
    return (
        f'<div class="table-scroll" role="region" aria-label="{_text(caption)}" tabindex="0">'
        f"<table><caption>{_text(caption)}</caption><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _framework_coverage(row: dict[str, Any], counts: dict[str, int]) -> tuple[object, object, bool]:
    observed = row.get("control_count")
    unknown = row.get("not_evaluated_control_count", 0)
    evaluated = (
        observed - unknown if type(observed) is int and type(unknown) is int and 0 <= unknown <= observed else None
    )
    total = counts.get(str(row.get("framework")))
    _, sufficient = readiness_coverage(evaluated, total)
    return evaluated, total, sufficient


def _fallback_html(app_data: dict[str, Any]) -> str:
    """Render the frozen report, including when the console is installed.

    Keep the original JSON payload byte-semantically recoverable. HTML entities
    are not decoded in a script raw-text element; JSON Unicode escapes safely
    preserve markup-like evidence without creating executable tags.
    """
    payload = json.dumps(app_data, sort_keys=True, default=str).replace("<", "\\u003c").replace("&", "\\u0026")
    assessment = app_data.get("posture", {})
    posture = assessment.get("posture", {})
    frameworks = assessment.get("frameworks", [])
    counts = app_data.get("framework_catalog_counts", {})
    framework_rows: list[list[object]] = []
    sufficient = bool(frameworks)
    for row in frameworks:
        evaluated, total, covered = _framework_coverage(row, counts)
        sufficient = sufficient and covered
        framework_rows.append(
            [
                row.get("framework"),
                f"{evaluated if evaluated is not None else '—'} / {total if total is not None else '—'}",
                f"{row.get('score', '—')}%" if covered else "Insufficient coverage",
                ("Ready" if row.get("state") == "ready" else "Needs attention") if covered else "Insufficient coverage",
            ]
        )
    score = f"{posture.get('score', '—')}%" if sufficient else "Insufficient coverage" if frameworks else "Not assessed"
    metrics = [
        ("Assessment score", score),
        ("Observed controls", posture.get("control_count", 0)),
        ("Open findings", posture.get("open_violation_count", 0)),
        ("Evidence rows", len(app_data.get("events", []))),
    ]
    cards = "".join(
        f'<div class="metric"><dt>{_text(label)}</dt><dd>{_text(value)}</dd></div>' for label, value in metrics
    )
    coverage = _table(
        ["Framework", "Evaluated / catalog", "Score", "Status"],
        framework_rows,
        caption="Framework coverage",
        empty="No frameworks were assessed in this saved report.",
    )
    findings = _table(
        ["Control", "Severity", "Asset", "Owner"],
        [
            [row.get(key) for key in ("control_id", "severity", "asset_id", "asset_owner")]
            for row in assessment.get("violations", [])
        ],
        caption="Recorded findings",
        empty="No open findings were recorded. This does not establish complete evidence coverage.",
    )
    controls = _table(
        ["Control", "Title", "Status", "Owner"],
        [[row.get(key) for key in ("control_id", "title", "status", "owner")] for row in app_data.get("controls", [])],
        caption="Recorded control results",
        empty="No control results were recorded.",
    )
    notice = (
        '<aside role="note">Contains synthetic demonstration evidence; synthetic rows are not production proof.</aside>'
        if app_data.get("synthetic_fixture") is True
        else ""
    )
    return _REPORT_TEMPLATE.format(
        payload=payload,
        notice=notice,
        cards=cards,
        evaluated=_text(assessment.get("evaluated_at")),
        digest=_text(assessment.get("assessment_hash")),
        coverage=coverage,
        findings=findings,
        controls=controls,
    )


_REPORT_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>GRC Lake Overview — frozen evidence report</title>
<style>
:root{{color-scheme:light;font-family:system-ui,-apple-system,sans-serif;color:#182335;background:#edf2f7}}
*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:1120px;margin:auto;padding:40px 24px 64px}}
header{{border-top:4px solid #3656d6;padding-top:22px;margin-bottom:24px}}
.brand{{color:#3656d6;font-weight:750;letter-spacing:.02em}}h1{{font-size:36px;line-height:1.15;margin:16px 0 10px}}
h2{{font-size:20px;margin:0 0 12px}}p{{line-height:1.65}}.muted,dt{{color:#526174}}
.meta{{font-size:14px}}aside{{background:#e9f1ff;border-left:4px solid #3656d6;border-radius:6px;padding:16px;margin:20px 0;line-height:1.6}}
.metrics{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:24px 0}}
.metric,section{{background:#fff;border:1px solid #d7e0eb;border-radius:12px;padding:20px}}
dt{{font-size:14px}}dd{{font-size:23px;font-weight:650;line-height:1.3;margin:12px 0 0;overflow-wrap:anywhere}}
section{{margin-top:18px}}.table-scroll{{overflow-x:auto;max-width:100%}}table{{border-collapse:collapse;width:100%;text-align:left;font-size:14px}}
caption{{text-align:left;font-weight:650;padding:0 0 14px}}th{{background:#f3f6fa;color:#435268;font-weight:650}}
th,td{{padding:12px;border-bottom:1px solid #e2e8f0;vertical-align:top;overflow-wrap:anywhere}}td{{max-width:340px}}
summary{{cursor:pointer;font-weight:650;padding:4px 0 16px}}code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere;font-size:12px}}
footer{{margin-top:24px;border-top:1px solid #ccd6e3;padding-top:16px}}:focus-visible{{outline:3px solid #3656d6;outline-offset:3px}}
@media(max-width:640px){{main{{padding:24px 14px 40px}}.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}h1{{font-size:30px}}section{{padding:16px}}}}
@media print{{:root{{background:#fff}}main{{max-width:none;padding:0}}section,.metric{{break-inside:avoid}}details{{display:block}}details::details-content{{content-visibility:visible;display:block}}}}
</style></head><body>
<script id="app-data" type="application/json">{payload}</script>
<main><header><div class="brand">GRC Lake · Frozen evidence report</div><h1>Overview</h1>
<p class="muted">Saved assessment and evidence for offline review. Values reflect the recorded evaluation; this file does not refresh evidence or connect to an API.</p>
<p class="meta"><strong>Evaluated at:</strong> {evaluated}</p></header>
{notice}<dl class="metrics">{cards}</dl>
<section><h2>Coverage and results</h2><p class="muted">Scores require at least 50% evaluated coverage of each observed framework's catalog. Catalog counts reflect the installed catalog at export. Scores describe assessed controls and are not an audit opinion.</p>{coverage}</section>
<section><h2>Findings</h2>{findings}</section>
<section><details><summary>Control results</summary>{controls}</details></section>
<footer><p class="meta"><strong>Recorded assessment digest:</strong> <code>{digest}</code></p>
<p class="muted">The embedded JSON preserves the report data for further review. This HTML file is a presentation of that data; it does not authenticate the evidence or verify its history.</p></footer>
</main></body></html>
"""
