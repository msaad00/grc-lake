"""OSCAL export: map TrustOps's control model into NIST's interchange format.

OSCAL (the Open Security Controls Assessment Language) is NIST's JSON/XML/YAML
format for control catalogs, component implementations, and assessment
results — the format auditor and GRC tooling ecosystems actually consume.
TrustOps's own control model (the CCF safeguards in ``controls/safeguards.json``
and the 942-requirement catalog in ``controls/catalog.json``) predates and is
richer than what OSCAL needs, so this module is a one-way projection: it reads
the existing model and emits two of the OSCAL layer models, it does not import
OSCAL or make it a source of truth.

Two models are covered:

* **Component Definition** (:func:`build_component_definition`) — one OSCAL
  ``component`` per CCF safeguard, with ``control-implementations`` pointing at
  the framework requirements it satisfies.
* **Assessment Results** (:func:`build_assessment_results`) — one OSCAL
  ``finding``/``observation`` pair per evaluated control in a lake's current
  (or a pinned point-in-time) posture.

Only confirmed safeguard→requirement mappings become OSCAL
``implemented-requirements``: maintainer-reviewed ones shipped in
``controls/safeguards.json``, plus mappings the tenant's own reviewers approved
(pass the payload from
:func:`security_lakehouse.mapping_review.effective_safeguards`). Each carries a
``trustops-review-state`` prop, and org-reviewed ones also name the reviewer,
decision time, and decision id. A ``proposed`` mapping is curation-queue state
and OSCAL has no field to mark an implemented requirement as unconfirmed, so
emitting it would read to auditor tooling as an asserted claim; org-rejected
mappings are withheld for the same reason. The state is decided by
:func:`security_lakehouse.safeguards.effective_review_state`.

Schema reference: <https://pages.nist.gov/OSCAL/>. Structural correctness is
checked in ``tests/test_oscal.py`` against the vendored OSCAL v1.2.3 JSON
Schema in ``controls/oscal/`` (see ``controls/oscal/README.md``).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.assessment import load_snapshot
from security_lakehouse.catalog import load_control_catalog, load_framework_registry
from security_lakehouse.generations import generation_identity
from security_lakehouse.io import read_jsonl, resolve_path
from security_lakehouse.models import utc_iso
from security_lakehouse.safeguards import (
    ATTESTABLE_STATES,
    REVIEW_STATE_LABELS,
    effective_review_state,
    load_ccf_families,
    load_safeguards,
)

# The exact OSCAL release this module targets and is structurally validated
# against (controls/oscal/*.json). Bump together with the vendored schemas.
OSCAL_VERSION = "1.2.3"

JsonObject = dict[str, Any]

# Fixed namespace so every emitted uuid is a deterministic function of its
# inputs (uuid5) rather than random (uuid4) -- re-exporting the same safeguard
# or control posture twice produces byte-identical OSCAL, which is what makes
# the output diffable and the tests reproducible.
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/msaad00/trustops-security-data-lake/oscal")

_INVALID_TOKEN_CHARS = re.compile(r"[^A-Za-z0-9._-]")

# TrustOps status vocabulary (written by the pipeline into
# gold/control_posture.jsonl -- see security_lakehouse.pipeline) mapped to
# OSCAL's finding-target objective-status. OSCAL only has two states,
# satisfied/not-satisfied; stale evidence and an unevaluated control are both
# "not-satisfied, reason other" rather than "satisfied" -- an auditor reading
# the export must never see an unconfirmed or unevaluated control reported as
# passing.
_STATUS_TO_OSCAL: dict[str, tuple[str, str]] = {
    "pass": ("satisfied", "pass"),
    "fail": ("not-satisfied", "fail"),
    "stale": ("not-satisfied", "other"),
    "not_evaluated": ("not-satisfied", "other"),
}


def _oscal_token(value: str) -> str:
    """Return a valid OSCAL token derived from ``value``.

    OSCAL control/objective ids are XML NCName tokens: a leading letter or
    underscore, then letters, digits, ``.``, ``-``, or ``_``. Most TrustOps
    control ids already qualify (``SOC2-CC6.1``, ``CIS-AWS-1.10``), but HIPAA
    ids carry parentheses (``HIPAA-164.308(a)(1)(ii)(A)``) that the token
    grammar forbids. Disallowed characters become ``-``; nothing is dropped
    silently -- callers also record the original id verbatim in a
    ``trustops-control-id`` prop, so the sanitization is never the only copy.
    """
    token = _INVALID_TOKEN_CHARS.sub("-", value.strip())
    token = re.sub(r"-{2,}", "-", token).strip("-")
    if not token:
        return "x"
    if not re.match(r"^[A-Za-z_]", token):
        token = f"x-{token}"
    return token


def _uuid5(*parts: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, "/".join(parts)))


def _prop(name: str, value: Any) -> JsonObject:
    return {"name": name, "value": str(value)}


def build_component_definition(
    safeguards_payload: JsonObject | None = None,
    catalog: dict[str, JsonObject] | None = None,
    *,
    now: datetime | None = None,
    lake_dir: str | Path | None = None,
) -> JsonObject:
    """Build an OSCAL component-definition from the CCF safeguards + catalog.

    Each safeguard in ``safeguards_payload`` (default: ``controls/safeguards.json``
    with the org review decisions recorded in ``lake_dir``, when given) becomes one OSCAL
    ``component`` of type ``process-procedure`` -- a safeguard is an operated
    control, not shipped software. Its reviewed ``satisfies`` entries are
    grouped by ``framework_id`` into one ``control-implementation`` per
    framework, each carrying the ``implemented-requirements`` for that
    framework's control ids. A safeguard with no reviewed mappings still
    becomes a component; it just carries no ``control-implementations`` key
    (OSCAL requires the array to be nonempty when present, and does not
    require at least one).
    """
    if safeguards_payload is not None:
        payload = safeguards_payload
    elif lake_dir is not None:
        from security_lakehouse.mapping_review import effective_safeguards

        payload = effective_safeguards(lake_dir)
    else:
        payload = load_safeguards()
    controls = catalog if catalog is not None else load_control_catalog()
    registry = load_framework_registry()
    families = load_ccf_families()
    moment = now or datetime.now(UTC)

    components: list[JsonObject] = []
    for entry in payload.get("safeguards", []):
        safeguard_id = str(entry["safeguard_id"])
        reviewed = [
            member for member in entry.get("satisfies", []) if effective_review_state(member) in ATTESTABLE_STATES
        ]
        by_framework: dict[str, list[JsonObject]] = {}
        for member in reviewed:
            by_framework.setdefault(str(member.get("framework_id")), []).append(member)

        control_implementations: list[JsonObject] = []
        for framework_id in sorted(by_framework):
            members = sorted(by_framework[framework_id], key=lambda m: str(m.get("control_id")))
            framework = registry.get(framework_id, {})
            source = str(framework.get("official_source_url") or f"urn:trustops:framework:{framework_id}")
            implemented_requirements = []
            for member in members:
                control_id = str(member["control_id"])
                control = controls.get(control_id, {})
                state = effective_review_state(member)
                props = [
                    _prop("trustops-control-id", control_id),
                    _prop("trustops-safeguard-id", safeguard_id),
                    _prop("trustops-role", member.get("role", "equivalent")),
                    _prop("trustops-review-state", REVIEW_STATE_LABELS[state]),
                ]
                org_review = member.get("org_review")
                if state == "org_reviewed" and isinstance(org_review, dict):
                    props.extend(
                        [
                            _prop("trustops-reviewed-by", org_review.get("reviewer")),
                            _prop("trustops-reviewed-at", org_review.get("decided_at")),
                            _prop("trustops-review-decision-id", org_review.get("decision_id")),
                        ]
                    )
                implemented_requirements.append(
                    {
                        "uuid": _uuid5("implemented-requirement", safeguard_id, control_id),
                        "control-id": _oscal_token(control_id),
                        "description": str(
                            control.get("evidence_requirement")
                            or entry.get("evidence_requirement")
                            or f"{safeguard_id} implements {control_id}."
                        ),
                        "props": props,
                    }
                )
            control_implementations.append(
                {
                    "uuid": _uuid5("control-implementation", safeguard_id, framework_id),
                    "source": source,
                    "description": (
                        f"{entry.get('title', safeguard_id)} — reviewed mappings to "
                        f"{framework.get('name', framework_id)}."
                    ),
                    "implemented-requirements": implemented_requirements,
                }
            )

        component: JsonObject = {
            "uuid": _uuid5("component", safeguard_id),
            "type": "process-procedure",
            "title": str(entry.get("title", safeguard_id)),
            "description": str(
                entry.get("objective") or entry.get("evidence_requirement") or entry.get("title", safeguard_id)
            ),
            "props": [
                _prop("trustops-safeguard-id", safeguard_id),
                _prop("risk-domain", entry.get("risk_domain", "")),
                _prop("trustops-category", families.get(str(entry.get("risk_domain")), {}).get("category", "")),
                _prop("owner", entry.get("owner", "")),
            ],
        }
        # `control-implementations` requires minItems:1 when present, but is not
        # itself required -- a safeguard with no reviewed mappings yet (all
        # proposed, or none at all) omits the key rather than emitting `[]`.
        if control_implementations:
            component["control-implementations"] = control_implementations
        components.append(component)

    return {
        "component-definition": {
            "uuid": _uuid5("component-definition", "trustops-ccf"),
            "metadata": {
                "title": "TrustOps Common Control Framework — Component Definition",
                "last-modified": utc_iso(moment),
                "version": moment.strftime("%Y-%m-%d"),
                "oscal-version": OSCAL_VERSION,
            },
            "components": components,
        }
    }


def _import_ap_href(posture_payload: JsonObject) -> str:
    """Return a URI identifying the control basis this assessment was run against.

    TrustOps has no separate OSCAL Assessment Plan document, so this points at
    the content-addressed catalog bundle (framework + control versions in
    force) instead -- the closest TrustOps equivalent of "what was assessed
    against". Point-in-time snapshots pin ``catalog_bundle`` at freeze time
    (see :func:`security_lakehouse.assessment.write_assessment_snapshot`);
    current posture has no pinned bundle, so this falls back to the active
    bundle, and finally to an unqualified marker if neither is reachable.
    """
    bundle = posture_payload.get("catalog_bundle")
    if isinstance(bundle, dict) and bundle.get("bundle_sha256"):
        return f"urn:trustops:catalog-bundle:{bundle['bundle_sha256']}"
    try:
        from security_lakehouse.catalog_versions import bundle_summary

        bundle = bundle_summary()
        if isinstance(bundle, dict) and bundle.get("bundle_sha256"):
            return f"urn:trustops:catalog-bundle:{bundle['bundle_sha256']}"
    except (OSError, ValueError, KeyError):
        return "urn:trustops:catalog-bundle:unknown"
    return "urn:trustops:catalog-bundle:unknown"


def build_assessment_results(
    lake_dir: str | Path,
    *,
    snapshot_id: str | None = None,
    now: datetime | None = None,
) -> JsonObject:
    """Build OSCAL assessment-results from one lake's evaluated control posture.

    Reads ``gold/control_posture.jsonl`` -- the per-control ``pass``/``fail``/
    ``stale``/``not_evaluated`` rows the pipeline writes for every generation
    (see :mod:`security_lakehouse.pipeline`) -- and turns each row into one
    OSCAL ``finding`` backed by one ``observation``.

    ``snapshot_id`` pins the result metadata (``evaluated_at``, content
    version, the catalog bundle referenced by ``import-ap``) to a recorded
    point-in-time snapshot written by
    :func:`security_lakehouse.assessment.write_assessment_snapshot`. The
    findings themselves always come from the lake's current
    ``gold/control_posture.jsonl`` -- snapshots persist aggregate framework
    scores and open violations, not a full per-control row set, so there is no
    frozen per-control detail to reconstruct for an older snapshot. Pass
    ``snapshot_id=None`` (the default) for the current posture, where this
    distinction does not apply.
    """
    lake = resolve_path(lake_dir)
    controls = read_jsonl(lake / "gold" / "control_posture.jsonl", missing_ok=True, base_dir=lake)
    moment = now or datetime.now(UTC)
    started = utc_iso(moment)

    if snapshot_id is not None:
        # A pinned snapshot already carries its own evaluated_at/assessment_hash/
        # generation as recorded metadata -- read it, no recomputation needed.
        posture_payload = load_snapshot(lake, snapshot_id)
        evaluated_at = str(posture_payload.get("evaluated_at") or started)
        assessment_hash = posture_payload.get("assessment_hash")
        version = str(assessment_hash)[:12] if assessment_hash else moment.strftime("%Y%m%dT%H%M%SZ")
        generation = posture_payload.get("generation")
    else:
        # The live case only needs evaluated_at/a version/generation -- not a
        # full posture recomputation (violations, evidence freshness, framework
        # scores). Hash the control rows actually being exported instead of
        # reusing build_current_posture()'s unrelated posture-wide hash, and
        # source the generation identity directly -- both are cheap reads.
        evaluated_at = started
        canonical = json.dumps(
            sorted(controls, key=lambda r: str(r.get("control_id"))),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        assessment_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        version = assessment_hash[:12]
        generation = generation_identity(lake)
        # build_current_posture() never sets catalog_bundle (that's a
        # snapshot-only field written by write_assessment_snapshot), so an
        # empty payload here reproduces the prior fallback behavior in
        # _import_ap_href exactly.
        posture_payload = {}

    generation_id = str(generation.get("generation_id")) if isinstance(generation, dict) else "current"
    subject_uuid = _uuid5("assessment-subject", generation_id)

    observations: list[JsonObject] = []
    findings: list[JsonObject] = []
    control_selections: list[JsonObject] = []
    for row in sorted(controls, key=lambda r: str(r.get("control_id"))):
        control_id = str(row.get("control_id") or "")
        if not control_id:
            continue
        status = str(row.get("status") or "not_evaluated")
        state, reason = _STATUS_TO_OSCAL.get(status, ("not-satisfied", "other"))
        token = _oscal_token(control_id)
        control_selections.append({"control-id": token})

        observation_uuid = _uuid5("observation", control_id, version)
        observation: JsonObject = {
            "uuid": observation_uuid,
            "title": f"{control_id} evaluation",
            "description": str(row.get("title") or f"Automated evaluation of {control_id}."),
            "methods": ["TEST"],
            "types": ["finding"],
            "subjects": [{"subject-uuid": subject_uuid, "type": "inventory-item"}],
            "collected": str(row.get("latest_event_time") or evaluated_at),
        }
        reasons = row.get("rule_reasons")
        if isinstance(reasons, list) and reasons:
            observation["remarks"] = "; ".join(str(item) for item in reasons)
        observations.append(observation)

        findings.append(
            {
                "uuid": _uuid5("finding", control_id, version),
                "title": f"{control_id} — {status}",
                "description": str(row.get("title") or control_id),
                "target": {
                    "type": "objective-id",
                    "target-id": f"{token}_obj",
                    "status": {"state": state, "reason": reason},
                },
                "props": [
                    _prop("trustops-control-id", control_id),
                    _prop("trustops-status", status),
                    _prop("framework", row.get("framework", "")),
                ],
                "related-observations": [{"observation-uuid": observation_uuid}],
            }
        )

    # OSCAL requires a nonempty `include-controls` list when that key is
    # present at all; an empty lake (no evaluated controls yet) has nothing to
    # list, so it selects `include-all` instead of emitting an invalid empty
    # array.
    control_selection: JsonObject = (
        {"include-controls": control_selections} if control_selections else {"include-all": {}}
    )
    result: JsonObject = {
        "uuid": _uuid5("result", version),
        "title": "TrustOps continuous control assessment",
        "description": "Automated OSCAL assessment result generated from TrustOps deterministic control evaluation.",
        "start": started,
        "reviewed-controls": {
            "control-selections": [control_selection],
        },
    }
    # Both arrays require minItems:1 when present, but neither is required --
    # a lake with no evaluated controls yet omits them rather than emitting an
    # invalid empty array.
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings

    return {
        "assessment-results": {
            "uuid": _uuid5("assessment-results", version),
            "metadata": {
                "title": "TrustOps Assessment Results",
                "last-modified": evaluated_at,
                "version": version,
                "oscal-version": OSCAL_VERSION,
            },
            "import-ap": {"href": _import_ap_href(posture_payload)},
            "results": [result],
        }
    }
