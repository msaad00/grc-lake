#!/usr/bin/env bash
# GRC Lake posture gate — evaluate /api/v1/posture/current and control-tests against thresholds.
set -euo pipefail

GRC_LAKE_URL="${GRC_LAKE_URL-${TRUSTOPS_URL:-}}"
GRC_LAKE_API_TOKEN="${GRC_LAKE_API_TOKEN-${TRUSTOPS_API_TOKEN:-}}"
CORRELATION_ID="${CORRELATION_ID:-}"
MIN_SCORE="${MIN_SCORE:-0}"
MAX_CRITICAL_VIOLATIONS="${MAX_CRITICAL_VIOLATIONS:-0}"
MAX_OPEN_VIOLATIONS="${MAX_OPEN_VIOLATIONS:--1}"
MAX_FAILING_CONTROL_TESTS="${MAX_FAILING_CONTROL_TESTS:-0}"
ALLOWED_FAILING_CONTROLS="${ALLOWED_FAILING_CONTROLS:-}"
FRAMEWORK="${FRAMEWORK:-}"
FAIL_ON_STALE_EVIDENCE="${FAIL_ON_STALE_EVIDENCE:-false}"

if [[ -z "${GRC_LAKE_URL}" ]]; then
  echo "::error title=GRC Lake posture gate::GRC_LAKE_URL is required"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "::error title=GRC Lake posture gate::jq is required on the runner"
  exit 1
fi

base="${GRC_LAKE_URL%/}"
posture_endpoint="${base}/api/v1/posture/current"

curl_args=(-fsS -H "Accept: application/json")
if [[ -n "${GRC_LAKE_API_TOKEN}" ]]; then
  curl_args+=(-H "Authorization: Bearer ${GRC_LAKE_API_TOKEN}")
fi
if [[ -n "${CORRELATION_ID}" ]]; then
  curl_args+=(-H "X-Correlation-ID: ${CORRELATION_ID}")
fi

response=""
if ! response="$(curl "${curl_args[@]}" "${posture_endpoint}")"; then
  echo "::error title=GRC Lake posture gate::Failed to reach ${posture_endpoint}"
  exit 1
fi

if ! echo "${response}" | jq -e '.data.posture' >/dev/null 2>&1; then
  detail="$(echo "${response}" | jq -r '.errors[0].detail // "unexpected response"')"
  echo "::error title=GRC Lake posture gate::${detail}"
  exit 1
fi

posture="$(echo "${response}" | jq -c '.data.posture')"
score="$(echo "${posture}" | jq -r '.score // empty')"
state="$(echo "${posture}" | jq -r '.state // "unknown"')"
open_count="$(echo "${posture}" | jq -r '.open_violation_count // 0')"
critical_count="$(echo "${posture}" | jq -r '.critical_violation_count // 0')"
failed_tests="$(echo "${posture}" | jq -r '.failed_control_test_count // 0')"
stale_count="$(echo "${response}" | jq -r '.data.posture.stale_evidence_count // .data.evidence_freshness.stale_count // 0')"

if [[ -z "${score}" ]]; then
  echo "::error title=GRC Lake posture gate::Posture score missing from response"
  exit 1
fi

failing_controls=()
if [[ "${MAX_FAILING_CONTROL_TESTS}" != "-1" || -n "${ALLOWED_FAILING_CONTROLS}" ]]; then
  control_args=(-G "${curl_args[@]}" "${base}/api/v1/control-tests")
  control_args+=(--data-urlencode "result=fail")
  control_args+=(--data-urlencode "sort=-confidence_score")
  control_args+=(--data-urlencode "limit=50")
  if [[ -n "${FRAMEWORK}" ]]; then
    control_args+=(--data-urlencode "framework=${FRAMEWORK}")
  fi
  control_response=""
  if ! control_response="$(curl "${control_args[@]}")"; then
    echo "::error title=GRC Lake posture gate::Could not read failing control tests from ${base}/api/v1/control-tests"
    exit 1
  fi
  if ! echo "${control_response}" | jq -e '.data | type == "array"' >/dev/null 2>&1; then
    echo "::error title=GRC Lake posture gate::Unexpected response from ${base}/api/v1/control-tests"
    exit 1
  fi
  while IFS= read -r control_id; do
    [[ -n "${control_id}" ]] && failing_controls+=("${control_id}")
  done < <(echo "${control_response}" | jq -r '.data[]?.control_id // empty')
fi

gate_failing_count="${failed_tests}"
if [[ -n "${ALLOWED_FAILING_CONTROLS}" ]]; then
  IFS=',' read -ra allowed <<<"${ALLOWED_FAILING_CONTROLS}"
  unexpected_failures=()
  gate_failing_count=0
  for control_id in "${failing_controls[@]+"${failing_controls[@]}"}"; do
    allowed_match=false
    for item in "${allowed[@]}"; do
      trimmed="$(echo "${item}" | xargs)"
      if [[ "${control_id}" == "${trimmed}" ]]; then
        allowed_match=true
        break
      fi
    done
    if [[ "${allowed_match}" == "false" ]]; then
      unexpected_failures+=("${control_id}")
      gate_failing_count=$((gate_failing_count + 1))
    fi
  done
  # The control-tests page is capped; failures that were not fetched cannot be
  # matched against the allowlist, so they count as unexpected.
  fetched_count=0
  for _ in "${failing_controls[@]+"${failing_controls[@]}"}"; do
    fetched_count=$((fetched_count + 1))
  done
  if (( failed_tests > fetched_count )); then
    gate_failing_count=$((gate_failing_count + failed_tests - fetched_count))
  fi
  failing_controls=("${unexpected_failures[@]+"${unexpected_failures[@]}"}")
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "posture_score=${score}"
    echo "posture_state=${state}"
    echo "open_violation_count=${open_count}"
    echo "critical_violation_count=${critical_count}"
    echo "failed_control_test_count=${gate_failing_count}"
  } >>"${GITHUB_OUTPUT}"
fi

echo "GRC Lake posture gate"
echo "  correlation: ${CORRELATION_ID:-<none>}"
echo "  score: ${score}"
echo "  state: ${state}"
echo "  open violations: ${open_count}"
echo "  critical violations: ${critical_count}"
echo "  failing control tests: ${gate_failing_count}"
echo "  stale evidence rows: ${stale_count}"

if [[ -n "${failing_controls[*]-}" ]]; then
  echo "  failing controls:"
  for control_id in "${failing_controls[@]-}"; do
    [[ -z "${control_id}" ]] && continue
    echo "    - ${control_id}"
  done
fi

failures=()

if awk -v score="${score}" -v min="${MIN_SCORE}" 'BEGIN { exit (score + 0 >= min + 0) ? 0 : 1 }'; then
  :
else
  failures+=("posture score ${score} is below minimum ${MIN_SCORE}")
fi

if awk -v count="${critical_count}" -v max="${MAX_CRITICAL_VIOLATIONS}" 'BEGIN { exit (count + 0 <= max + 0) ? 0 : 1 }'; then
  :
else
  failures+=("critical violations ${critical_count} exceed maximum ${MAX_CRITICAL_VIOLATIONS}")
fi

if [[ "${MAX_OPEN_VIOLATIONS}" != "-1" ]]; then
  if awk -v count="${open_count}" -v max="${MAX_OPEN_VIOLATIONS}" 'BEGIN { exit (count + 0 <= max + 0) ? 0 : 1 }'; then
    :
  else
    failures+=("open violations ${open_count} exceed maximum ${MAX_OPEN_VIOLATIONS}")
  fi
fi

if [[ "${MAX_FAILING_CONTROL_TESTS}" != "-1" ]]; then
  if awk -v count="${gate_failing_count}" -v max="${MAX_FAILING_CONTROL_TESTS}" 'BEGIN { exit (count + 0 <= max + 0) ? 0 : 1 }'; then
    :
  else
    if [[ -n "${failing_controls[*]-}" ]]; then
      failures+=(
        "failing control tests ${gate_failing_count} exceed maximum ${MAX_FAILING_CONTROL_TESTS} (${failing_controls[*]-})"
      )
    else
      failures+=(
        "failing control tests ${gate_failing_count} exceed maximum ${MAX_FAILING_CONTROL_TESTS}"
      )
    fi
  fi
fi

if [[ "${FAIL_ON_STALE_EVIDENCE}" == "true" && "${stale_count}" != "0" ]]; then
  failures+=("stale or expired evidence on ${stale_count} control(s)")
fi

if ((${#failures[@]} > 0)); then
  for reason in "${failures[@]}"; do
    echo "::error title=GRC Lake posture gate::${reason}"
  done
  exit 1
fi

echo "Posture gate passed."
