"""Portable auditor workpapers with immutable inputs and explicitly draft prose."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from security_lakehouse.control_assurance import assess_control_plan, evidence_reference
from security_lakehouse.generations import generation_reader
from security_lakehouse.io import canonical_sha256, file_sha256, read_json, read_jsonl
from security_lakehouse.population_reconciliation import assess_population


@generation_reader
def build_workpaper(
    lake: Path,
    *,
    plan: dict[str, Any],
    baseline: dict[str, Any],
    narrative: str = "",
    citations: list[str] | None = None,
    remediation_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if plan.get("tenant_id") != baseline.get("tenant_id") or plan.get("as_of") != baseline.get("as_of"):
        raise ValueError("test plan and population baseline must share tenant and cutoff")
    population = assess_population(lake, baseline)
    declared_assets = {
        (account["source_tenant_id"], asset_id)
        for account in baseline["inventory"]["accounts"]
        for asset_id in account["asset_ids"]
    }
    assurance = assess_control_plan(lake, plan, declared_assets=declared_assets)
    referenced: set[str] = set()
    for control in assurance["controls"]:
        referenced.update(row["event_id"] for row in control["design"]["evidence"])
        referenced.update(row["event_id"] for row in control["operating"]["samples"])
        referenced.update(control["operating"]["deviation_event_ids"])
        referenced.update(control["operating"]["invalid_event_ids"])
        referenced.update(row["event_id"] for row in control.get("assessment_context", {}).get("evidence", []))
    events = read_jsonl(lake / "silver/normalized_events.jsonl")
    evidence = {
        row["event_id"]: {**evidence_reference(row), "status": row["status"], "source": row["source"]}
        for row in events
        if row["event_id"] in referenced
    }
    citations = citations or []
    if len(narrative) > 10000 or len(citations) > 500 or len(set(citations)) != len(citations):
        raise ValueError("draft or citations exceed bounds or contain duplicates")
    if any(item not in evidence for item in citations) or (narrative.strip() and not citations):
        raise ValueError("draft prose requires valid citations to this workpaper's evidence")
    counts = Counter(row["operating"]["status"] for row in assurance["controls"])
    content = {
        "schema_version": "trustops.audit_workpaper.v1",
        "synthetic_fixture": any(row["source"] == "synthetic-audit-fixture" for row in events),
        "tenant_id": plan["tenant_id"],
        "plan": plan,
        "baseline": baseline,
        "generation": assurance["generation"],
        "assurance": assurance,
        "population": population,
        "evidence": dict(sorted(evidence.items())),
        "narrative": {
            "origin": "submitted_draft" if narrative.strip() else "deterministic_summary",
            "text": narrative.strip()
            or f"{counts['sample_pass']} control sample sets passed; {counts['sample_fail']} have observed deviations; {counts['insufficient_evidence']} have insufficient evidence. Population reconciliation: {population['status']}.",
            "citations": sorted(citations) if narrative.strip() else sorted(evidence),
            "status": "unreviewed",
        },
        "remediation": {
            "source": "application_state_snapshot" if remediation_records is not None else "not_included",
            "tasks": remediation_records or [],
        },
        "limitations": [
            "Machine results await human judgment and are not an audit opinion.",
            "Inventory completeness and provider collection are not independently verified.",
            "Samples do not establish statistical confidence or continuous operation between observations.",
            "Risk acceptance and workpaper approval never change control results.",
        ],
    }
    if len(json.dumps(content).encode()) > 2 * 1024 * 1024:
        raise ValueError("workpaper exceeds 2 MiB; split the assessment scope")
    return content


def render_workpaper(content: dict[str, Any], *, review: dict[str, Any] | None = None) -> str:
    # Rendering must be reproducible from the persisted JSON, whose keys are sorted.
    content = json.loads(json.dumps(content, sort_keys=True))

    def escape(value: Any) -> str:
        return html.escape(str(value), quote=True)

    controls = content["assurance"]["controls"]
    population = content["population"]
    counts = Counter(row["operating"]["status"] for row in controls)
    status = (review or {}).get("status", "draft")
    cards = []
    labels = {
        "sample_pass": "Passing samples",
        "sample_fail": "Observed deviation",
        "insufficient_evidence": "Evidence gap",
    }
    for control in controls:
        test = control["test_definition"]
        operating = control["operating"]
        rows = "".join(
            f"<tr><td>{escape(row['event_id'])}</td><td>{escape(row['asset_id'])}</td><td>{escape(row['event_time'])}</td><td><code>{escape(row['raw_sha256'])}</code></td></tr>"
            for row in operating["samples"]
        )
        mappings = ", ".join(
            f"{row['control_id']} ({row['effective_review_state']})" for row in control["requirement_mappings"]
        )
        context = control.get("assessment_context")
        context_html = ""
        if context:
            details = "".join(
                f"<p><strong>{escape(key.replace('_', ' ').title())}:</strong> {escape(context[key])}</p>"
                for key in ("provider", "responsibilities", "alternative_control")
                if key in context
            )
            context_html = (
                f'<section class="notice"><strong>Assessment context: {escape(context["state"].replace("_", " ").title())}</strong>'
                f"<p>{escape(context['rationale'])}</p>{details}"
                f'<p class="meta">Workpaper review: {escape(status)}. Period and generation bound; machine outcomes and scores remain unchanged.</p>'
                f'<p class="meta">Evidence: {escape(", ".join(context["evidence_event_ids"]))}</p></section>'
            )
        cards.append(f'''<article><div class="eyebrow">{escape(control["safeguard_id"])}</div><h3>{escape(test["activity"])}</h3>
<p class="meta">{escape(test["owner"])} · {escape(test["system"])} · {escape(test["frequency"])}</p>
<div class="results"><span>Design: <strong>{escape(control["design"]["status"].replace("_", " "))}</strong></span><span class="{escape(operating["status"])}">{escape(labels[operating["status"]])}</span></div>
{context_html}<p>{escape(test["procedure"])}</p><p class="meta">Planned windows: {operating["planned_windows"]} · Observed assets: {operating["observed_asset_count"]} · Selected records: {len(operating["samples"])}</p>
<details><summary>Inspect evidence and test rationale</summary><p>{escape(test["sampling_rationale"])}</p><p>Deviations: {escape(", ".join(operating["deviation_event_ids"]) or "None observed")}</p><pre>{escape(json.dumps(operating["gaps"], indent=2))}</pre><table><thead><tr><th>Event</th><th>Asset</th><th>Observed</th><th>Raw SHA-256</th></tr></thead><tbody>{rows}</tbody></table><p>Design records: {escape(", ".join(row["event_id"] for row in control["design"]["evidence"]))}</p><p>{escape(mappings)}</p></details></article>''')
    issues = "".join(
        f"<li><strong>{escape(name.replace('_', ' '))}: {section['count']}</strong><pre>{escape(json.dumps(section['items'], indent=2))}</pre>{'Additional details truncated' if section['truncated'] else ''}</li>"
        for name, section in population["issues"].items()
        if section["count"]
    )
    review_text = "Independent human review required. This draft does not certify control effectiveness."
    if review:
        review_text = f"Workpaper {status}. Reviewer: {review.get('reviewed_by') or 'pending'}. {review.get('review_rationale') or ''} Review acknowledges the workpaper; factual gaps remain unchanged."
    source_label = " · Synthetic demonstration" if content.get("synthetic_fixture") else ""
    if content.get("migration"):
        source_label += " · Migrated export (hash consistency only)"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TrustOps · Control audit workpaper</title><style>
:root{{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#192e39;background:#f4f6f7}}*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:1140px;margin:auto;padding:44px 32px}}header{{border-bottom:1px solid #ced9dd;padding-bottom:24px}}.eyebrow{{font-size:12px;letter-spacing:.1em;font-weight:700;color:#477080;text-transform:uppercase}}h1{{font-size:38px;letter-spacing:-.04em;margin:12px 0}}h2{{font-size:23px;margin:32px 0 15px}}h3{{font-size:19px;margin:10px 0}}p{{line-height:1.6}}.meta{{color:#506771;font-size:13px}}.badge{{display:inline-block;border:1px solid #b3c7d0;padding:5px 12px;border-radius:24px;font-size:12px;font-weight:700}}.notice{{border-left:3px solid #be8a30;background:#fff8e9;padding:13px 18px;font-size:14px;margin:20px 0}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:25px}}.metric,article{{background:white;border:1px solid #dbe3e6;border-radius:10px;padding:21px}}.metric strong{{display:block;font-size:30px;margin-bottom:5px}}.metric span{{font-size:13px;color:#506771}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}.results{{display:flex;gap:12px;justify-content:space-between;font-size:12px;background:#f4f7f8;padding:10px;border-radius:6px}}.sample_pass{{color:#11654d}}.sample_fail{{color:#aa382d}}.insufficient_evidence{{color:#815409}}details{{border-top:1px solid #e2e8eb;padding-top:12px;margin-top:16px;font-size:13px}}summary{{cursor:pointer;color:#265d75;font-weight:600}}table{{border-collapse:collapse;width:100%;font-size:11px}}td,th{{text-align:left;border-bottom:1px solid #dde5e8;padding:8px;overflow-wrap:anywhere}}pre,code{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px}}.lineage{{padding:20px;background:#e9f0f3;border-radius:10px}}footer{{margin-top:30px;font-size:12px;color:#506771}}@media(max-width:760px){{main{{padding:24px 18px}}.grid,.metrics{{grid-template-columns:1fr}}h1{{font-size:30px}}}}@media print{{body{{background:white}}main{{padding:0}}article{{break-inside:avoid}}details{{display:block}}.notice{{background:white}}}}
</style></head><body><main><header><div class="eyebrow">TrustOps / Auditor workpaper</div><h1>Control assurance, with the evidence.</h1><p>Design documentation, operating samples, and population gaps — reviewed as separate claims.</p><span class="badge">{escape(status.title())}{source_label}</span><p class="meta">Period {escape(content["plan"]["period_start"][:10])} → {escape(content["plan"]["period_end"][:10])} · Evidence cutoff {escape(content["plan"]["as_of"][:10])}</p></header>
<div class="notice">{escape(review_text)}</div><section class="metrics" aria-label="Assessment summary"><div class="metric"><strong>{len(controls)}</strong><span>Operated controls tested</span></div><div class="metric"><strong>{counts["sample_pass"]}</strong><span>Passing sample sets</span></div><div class="metric"><strong>{counts["sample_fail"]}</strong><span>Sets with deviations</span></div><div class="metric"><strong>{counts["insufficient_evidence"]}</strong><span>Sets with evidence gaps</span></div></section>
<h2>Control testing</h2><section class="grid">{"".join(cards)}</section><h2>Population completeness</h2><section class="lineage"><p><strong>{population["observed_asset_count"]} observed / {population["expected_asset_count"]} declared assets</strong> · {escape(population["status"].replace("_", " "))}</p><p>Inventory completeness is not independently verified. Collection receipts are operator supplied.</p><ul>{issues or "<li>No differences from the declared scope.</li>"}</ul></section>
<h2>Draft narrative</h2><p>{escape(content["narrative"]["text"])}</p><p class="meta">Source: {escape(content["narrative"]["origin"])} · Citations: {escape(", ".join(content["narrative"]["citations"]))}</p>
<details><summary>Evidence lineage and remediation receipts</summary><p>Generation {escape(content["generation"]["generation_id"])}</p><p>Content SHA-256 <code>{canonical_sha256(content)}</code></p><pre>{escape(json.dumps(content["evidence"], indent=2))}</pre><pre>{escape(json.dumps(content["remediation"], indent=2))}</pre></details><footer>{"<br>".join(escape(item) for item in content["limitations"])}</footer></main></body></html>"""


def export_workpaper(content: dict[str, Any], out: Path) -> None:
    rendered = render_workpaper(content)
    serialized = json.dumps(content, indent=2, sort_keys=True) + "\n"
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, value in (("workpaper.json", serialized), ("index.html", rendered)):
        with (out / name).open("x", encoding="utf-8") as stream:
            stream.write(value)
    manifest = {
        "schema_version": "trustops.workpaper_export.v1",
        "render_version": "trustops.workpaper_html.v1",
        "content_sha256": canonical_sha256(content),
        "files": {name: file_sha256(out / name) for name in ("index.html", "workpaper.json")},
    }
    with (out / "manifest.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def verify_workpaper_export(out: Path) -> dict[str, Any]:
    try:
        expected = {"manifest.json", "index.html", "workpaper.json"}
        if (
            out.is_symlink()
            or {path.name for path in out.iterdir()} != expected
            or any((out / name).is_symlink() or not (out / name).is_file() for name in expected)
        ):
            raise ValueError("unexpected export files")
        manifest = read_json(out / "manifest.json")
        valid = (
            isinstance(manifest, dict)
            and set(manifest) <= {"schema_version", "render_version", "content_sha256", "files"}
            and manifest.get("schema_version") == "trustops.workpaper_export.v1"
            and manifest.get("render_version", "trustops.workpaper_html.v1") == "trustops.workpaper_html.v1"
            and isinstance(manifest.get("files"), dict)
            and set(manifest["files"]) == {"index.html", "workpaper.json"}
        )
        valid = valid and all(file_sha256(out / name) == digest for name, digest in manifest["files"].items())
        content = read_json(out / "workpaper.json")
        valid = valid and canonical_sha256(content) == manifest["content_sha256"]
        valid = valid and (out / "index.html").read_text(encoding="utf-8") == render_workpaper(content)
    except (OSError, ValueError, KeyError, TypeError):
        valid = False
    return {"ok": bool(valid), "authentication": "hash_consistency_only; review identity requires server record"}
