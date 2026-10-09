"""Re-fetch official framework sources, recompute sha256, record content drift.

Runs as ``grc-lake frameworks sync`` (CLI) and on a cron via
``.github/workflows/framework-sync.yml``. The job is intentionally append-only
in spirit: it mutates ``frameworks/registry.json`` in place but only the
``source_sha256`` + ``pulled_at`` fields, and only when the upstream body has
changed (sha differs from what's in the registry). ``pulled_at`` is when the
current ``source_sha256`` was recorded, so re-fetching identical content leaves
the registry byte-identical and the scheduled job opens no drift PR.

When run with ``--open-pr`` and inside GitHub Actions, the workflow that calls
this CLI opens a pull request with the diff so a human reviewer ratifies the
drift before merging.

Network access is opt-in (``--allow-network``). Offline runs only mark every
framework as "skipped — network disabled" so unit tests don't make HTTP calls.

A source that is temporarily unavailable (HTTP 403, 429, or 5xx, or a network
failure) is ``transient``: ``report`` emits a warning annotation and exits 0. Any
other fetch error, such as a 404 or an invalid URL, means the registry entry
itself is wrong, so ``report`` emits an error annotation and exits 1.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import DEFAULT_FRAMEWORK_REGISTRY
from security_lakehouse.io import append_jsonl
from security_lakehouse.timeutil import utc_now_iso_z

PROJECT_URL = "https://github.com/msaad00/grc-lake"


def _package_version() -> str:
    try:
        return metadata.version("grc-lake")
    except metadata.PackageNotFoundError:
        return "0.0.0"


# Several regulator sites sit behind bot filters that 403 an opaque UA. Say
# who we are and where to reach the maintainers, in the conventional
# "compatible; name/version; +url" form crawlers use.
USER_AGENT = f"Mozilla/5.0 (compatible; trustops-framework-sync/{_package_version()}; +{PROJECT_URL})"
DEFAULT_TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 4
BASE_RETRY_DELAY_SECONDS = 2.0
MAX_RETRY_DELAY_SECONDS = 60.0
# 403 is included on purpose: CDN bot shields in front of regulator sites
# return it transiently under burst load, and a later retry often succeeds.
RETRYABLE_STATUS = frozenset({403, 408, 425, 429, 500, 502, 503, 504})
FETCH_ERRORS: tuple[type[BaseException], ...] = (
    urllib.error.URLError,
    http.client.HTTPException,
    TimeoutError,
    OSError,
    ValueError,
)


@dataclass(frozen=True)
class SyncResult:
    framework_id: str
    state: str  # "updated" | "unchanged" | "skipped" | "error"
    old_sha: str | None
    new_sha: str | None
    pulled_at: str | None
    reason: str | None
    # True only for an "error" caused by the upstream being unavailable.
    transient: bool = False


def is_transient_fetch_error(exc: BaseException) -> bool:
    """Whether a fetch failure is the upstream being unavailable rather than a broken source entry."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (403, 429) or exc.code >= 500
    if isinstance(exc, urllib.error.URLError):
        # urllib wraps socket, DNS, and TLS failures as an OSError reason; a str
        # reason such as "unknown url type" is a malformed registry URL.
        return isinstance(exc.reason, OSError)
    return isinstance(exc, (TimeoutError, ConnectionError, http.client.IncompleteRead))


def _retry_delay(attempt: int, exc: BaseException) -> float:
    if isinstance(exc, urllib.error.HTTPError) and exc.headers is not None:
        retry_after = (exc.headers.get("Retry-After") or "").strip()
        if retry_after.isdigit():
            return min(float(retry_after), MAX_RETRY_DELAY_SECONDS)
    return min(BASE_RETRY_DELAY_SECONDS * (2 ** (attempt - 1)), MAX_RETRY_DELAY_SECONDS)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRYABLE_STATUS
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError))


def _fetch(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/pdf,application/json;q=0.9,*/*;q=0.8",
        },
    )
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with opener(request, timeout=timeout) as response:
                return bytes(response.read())
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == MAX_ATTEMPTS or not _is_retryable(exc):
                raise
            sleep(_retry_delay(attempt, exc))
    raise AssertionError("unreachable")  # pragma: no cover


def sync_frameworks(
    registry_path: str | Path | None = None,
    *,
    allow_network: bool = False,
    fetcher: Any | None = None,
    history_path: str | Path | None = None,
    refresh_bundle_lock: bool = True,
) -> list[SyncResult]:
    """Sync every framework in the registry. Returns one SyncResult per framework.

    ``fetcher`` is an optional callable taking (url) -> bytes; tests inject a
    fake fetcher to avoid network. When ``allow_network`` is False and no
    fetcher is provided, every framework is marked ``skipped``.
    """
    path = Path(registry_path or DEFAULT_FRAMEWORK_REGISTRY)
    payload = json.loads(path.read_text(encoding="utf-8"))
    frameworks = payload.get("frameworks") or []
    if not isinstance(frameworks, list):
        raise ValueError("registry must contain a frameworks list")

    results: list[SyncResult] = []
    dirty = False
    for framework in frameworks:
        framework_id = str(framework.get("framework_id") or "")
        url = str(framework.get("official_source_url") or "")
        old_sha = framework.get("source_sha256")
        if not framework_id or not url:
            results.append(
                SyncResult(
                    framework_id=framework_id or "<unknown>",
                    state="error",
                    old_sha=old_sha,
                    new_sha=None,
                    pulled_at=framework.get("pulled_at"),
                    reason="registry entry missing framework_id or official_source_url",
                )
            )
            continue
        if fetcher is None and not allow_network:
            results.append(
                SyncResult(
                    framework_id=framework_id,
                    state="skipped",
                    old_sha=old_sha,
                    new_sha=None,
                    pulled_at=framework.get("pulled_at"),
                    reason="network disabled (--allow-network not set)",
                )
            )
            continue
        try:
            body = (fetcher or _fetch)(url)
        except FETCH_ERRORS as exc:
            # One regulator being down or blocking us must not cost the other
            # frameworks their refresh; the error is reported per framework.
            results.append(
                SyncResult(
                    framework_id=framework_id,
                    state="error",
                    old_sha=old_sha,
                    new_sha=None,
                    pulled_at=framework.get("pulled_at"),
                    reason=f"fetch failed: {exc.__class__.__name__}: {exc}",
                    transient=is_transient_fetch_error(exc),
                )
            )
            continue
        new_sha = hashlib.sha256(body).hexdigest()
        state = "unchanged" if new_sha == old_sha else "updated"
        pulled_at = framework.get("pulled_at")
        if state == "updated":
            dirty = True
            pulled_at = utc_now_iso_z()
            framework["pulled_at"] = pulled_at
            framework["source_sha256"] = new_sha
            # Append-only record of the source drift so the history of *what the
            # upstream said when* survives even before a human assigns a new
            # version label in the registry. History sits next to the registry
            # being synced so a tmp registry never writes to the repo's ledger.
            append_jsonl(
                Path(history_path) if history_path else path.parent / "history.jsonl",
                {
                    "framework_id": framework_id,
                    "version": framework.get("version"),
                    "old_source_sha256": old_sha,
                    "new_source_sha256": new_sha,
                    "official_source_url": url,
                    "pulled_at": pulled_at,
                },
            )
        results.append(
            SyncResult(
                framework_id=framework_id,
                state=state,
                old_sha=old_sha,
                new_sha=new_sha,
                pulled_at=pulled_at,
                reason=None,
            )
        )

    # Only a content change rewrites the registry. The scheduled job treats any
    # registry diff as drift, so an identical re-fetch must leave it untouched.
    if dirty:
        path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    # Re-lock the catalog bundle so source drift is reflected in the audit pin.
    # Only for the real default registry — the bundle spans repo-global controls
    # + crosswalk, so re-locking on a caller-supplied (e.g. tmp) registry would
    # mix paths and clobber the committed lockfile.
    if dirty and refresh_bundle_lock and registry_path is None:
        try:
            from security_lakehouse.catalog_versions import write_bundle_lock

            write_bundle_lock()
        except (OSError, ValueError) as exc:
            print(f"warning: catalog bundle lock was not refreshed: {exc}", file=sys.stderr)
    return results


def format_sync_report(payload: Mapping[str, Any]) -> str:
    """Render ``frameworks sync`` JSON output as Markdown for a PR body or job summary."""
    rows: Sequence[Mapping[str, Any]] = payload.get("results") or []
    counts = Counter(str(row.get("state")) for row in rows)
    order = ("updated", "unchanged", "skipped", "error")
    parts = [f"{counts[state]} {state}" for state in order if counts[state]]
    parts += [f"{n} {state}" for state, n in sorted(counts.items()) if state not in order]
    lines = [f"**Framework sync:** {', '.join(parts) or 'no frameworks'}", ""]
    errors = [row for row in rows if row.get("state") == "error"]
    if not errors:
        lines.append("No source errors.")
        return "\n".join(lines) + "\n"
    lines += [
        "These sources could not be fetched; their registry entries were left unchanged:",
        "",
        "| Framework | Reason |",
        "| --- | --- |",
    ]
    for row in errors:
        reason = str(row.get("reason") or "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{row.get('framework_id')}` | {reason} |")
    return "\n".join(lines) + "\n"


def _escape_annotation(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report_annotations(payload: Mapping[str, Any]) -> tuple[list[str], bool]:
    """GitHub Actions annotations for source errors, and whether any error is a real failure.

    An error row without ``transient: true`` fails closed: only a classified
    upstream outage is downgraded to a warning.
    """
    rows: Sequence[Mapping[str, Any]] = payload.get("results") or []
    lines: list[str] = []
    failed = False
    for row in rows:
        if row.get("state") != "error":
            continue
        transient = row.get("transient") is True
        failed = failed or not transient
        level = "warning" if transient else "error"
        message = _escape_annotation(f"{row.get('framework_id')}: {row.get('reason') or 'unknown error'}")
        lines.append(f"::{level} title=Framework sync::{message}")
    return lines, failed


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "report":
        print("usage: python -m security_lakehouse.framework_sync report <sync.json>", file=sys.stderr)
        return 2
    payload = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    sys.stdout.write(format_sync_report(payload))
    # stdout is the Markdown report the workflow redirects to a file; the
    # runner reads workflow commands from stderr as well.
    annotations, failed = report_annotations(payload)
    for line in annotations:
        print(line, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
