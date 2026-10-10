# Use Case: Just-In-Time Vendor Diligence Snapshot

This walkthrough shows the product as a lightweight internal compliance
assessment tool.

## Scenario

A customer asks for evidence that production AI systems have current access,
monitoring, runtime, and AI governance controls. The company needs an answer in
minutes, without manually assembling screenshots and spreadsheets.

## Run

```bash
make smoke
grc-lake assessment status --lake build/lakehouse
grc-lake assessment violations --lake build/lakehouse
grc-lake assessment snapshot \
  --lake build/lakehouse \
  --reason vendor_due_diligence
grc-lake serve --lake build/lakehouse --port 8787
```

Open:

```text
http://127.0.0.1:8787/
```

## What The Tool Produces

| Output          | Purpose                                             |
| --------------- | --------------------------------------------------- |
| current posture | live assessment state for humans and agents         |
| violations      | owner-ready control and asset gaps                  |
| snapshot        | point-in-time evidence package with assessment hash |
| console         | clickable review surface                            |
| API             | agent and automation interface                      |

## Evidence Path

```text
sample evidence
  -> normalized evidence
  -> SOC 2 + NIST AI RMF control catalog
  -> continuous assessment
  -> open violations
  -> point-in-time snapshot
```

## Screenshot

![GRC Lake dashboard screenshot](images/grc-lake-demo-dashboard.png)
