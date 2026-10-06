"""Human context is evidence-bound and never overwrites machine outcomes."""

import pytest

import test_audit_workpapers

workpaper_env = test_audit_workpapers.workpaper_env


def declaration(state):
    context = {"state": state, "rationale": "Inspect this bounded scope", "evidence_event_ids": ["day2-1"]}
    if state == "inherited":
        context.update(
            provider="Example provider", responsibilities="Provider runs the service; customer reviews access"
        )
    if state == "compensating":
        context.update(alternative_control="Independent daily review of changes")
    return context


@pytest.mark.parametrize("state", ["not_applicable", "inherited", "compensating"])
def test_context_survives_independent_review_without_hiding_failures(workpaper_env, state):
    _, client, headers, _, body = workpaper_env
    body["plan"]["controls"][1]["assessment_context"] = declaration(state)
    response = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"])
    assert response.status_code == 201, response.text
    row = response.json()["data"]
    context = row["content"]["assurance"]["controls"][1]["assessment_context"]
    assert context["state"] == state
    assert context["evidence"][0]["event_id"] == "day2-1"
    url = f"/api/v1/audit-workpapers/{row['id']}"
    review = {
        "decision": "approve",
        "rationale": "Reviewed the context and contrary evidence",
        "content_sha256": row["content_sha256"],
    }
    assert client.post(url + "/review", json=review, headers=headers["author"]).status_code == 403
    approved = client.post(url + "/review", json=review, headers=headers["reviewer"])
    assert approved.status_code == 200
    assert approved.json()["data"]["content"] == row["content"]
    assert row["content"]["assurance"]["controls"][1]["operating"]["status"] == "sample_fail"
    assert row["content"]["population"]["status"] == "incomplete"
    html = client.get(url + "/html", headers=headers["author"]).text
    assert state.replace("_", " ").title() in html
    assert "Observed deviation" in html
    assert "Assessment context" in html


@pytest.mark.parametrize(
    "patch",
    [
        {"state": "pass"},
        {"rationale": " "},
        {"evidence_event_ids": []},
        {"evidence_event_ids": ["invented"]},
        {"evidence_event_ids": ["day2-0"]},
        {"evidence_event_ids": ["day2-1", "day2-1"]},
        {"reviewed_by": "forged"},
        {"provider": " "},
        {"responsibilities": " "},
    ],
)
def test_context_rejects_unbound_evidence_forgery_and_incomplete_responsibility(workpaper_env, patch):
    _, client, headers, _, body = workpaper_env
    body["plan"]["controls"][1]["assessment_context"] = {**declaration("inherited"), **patch}
    response = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"])
    assert response.status_code == 400
