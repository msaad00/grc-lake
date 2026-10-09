"""Read caches preserve distributed publication and tenant isolation."""

from security_lakehouse import api_v1, assessment, graph, io
from security_lakehouse.distributed.objects import ObjectStore
from security_lakehouse.distributed.workspace import Runtime
from test_distributed_objects import MemoryObjects
from test_read_path_cache import MOMENT, _event, _legacy_lake


def test_cached_reads_follow_publication_across_private_replica_roots(catalog, tmp_path, monkeypatch):
    store = ObjectStore(catalog.config, client=MemoryObjects())
    writer = Runtime(catalog, store, tmp_path / "writer")
    reader = Runtime(catalog, store, tmp_path / "reader")
    monkeypatch.setattr(assessment, "_utcnow", lambda: MOMENT)
    for tenant in ("tenant-a", "tenant-b"):
        with writer.write(tenant) as lake:
            _legacy_lake(lake, [_event(tenant)])

    def check(runtime, tenant, ids):
        with runtime.read(tenant) as lake:
            for _ in range(2):
                posture = assessment.build_current_posture(lake)
                assert {row["event_id"] for row in posture["violations"]} == ids
                assert posture == assessment.build_current_posture(lake, now=MOMENT)
                status, page = api_v1.handle_get("/api/v1/evidence", {"limit": ["10"]}, lake)
                assert status == 200
                assert {row["event_id"] for row in page["data"]} == ids
                evidence = [
                    node for node in graph.build_compliance_graph(lake)["nodes"] if node["kind"] == "evidence_type"
                ]
                assert sum(node["event_count"] for node in evidence) == len(ids)
                # Response mutation must never affect another request or tenant.
                posture["violations"].clear()
                page["data"].clear()

    for runtime in (writer, reader):
        check(runtime, "tenant-a", {"tenant-a"})
        check(runtime, "tenant-b", {"tenant-b"})
    with writer.write("tenant-a") as lake:
        io.write_jsonl(lake / "silver/normalized_events.jsonl", [_event("tenant-a"), _event("new-a")])
    for runtime in (reader, writer):
        check(runtime, "tenant-a", {"tenant-a", "new-a"})
        check(runtime, "tenant-b", {"tenant-b"})
