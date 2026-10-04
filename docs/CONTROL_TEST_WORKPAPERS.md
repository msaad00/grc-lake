# Control design and period testing

`assessment test-plan` evaluates a versioned test plan against one verified sealed
generation. Plans name the operated CCF safeguard, activity, owner, system,
frequency, procedure, sample size, sampling rationale, design evidence IDs, and
closed assessment period. Requirement mappings come from the generation's CCF
catalog, with their review states, rather than from claims in the plan.

```sh
security-lakehouse pipeline run --raw examples/control-assurance/events.jsonl --out build/assurance-demo
security-lakehouse assessment test-plan --lake build/assurance-demo --plan examples/control-assurance/plan.json
```

The fixture uses five controls: privileged access, production changes, audit
logging, encryption, and AI model inventory. All records are synthetic. Change
management has a failing observation; AI inventory has a missing daily window.
The other three have passing samples. These are demonstrations, not operational
claims about this repository or a real organization.

## What the conclusions mean

- **Design documented:** each declared design record exists, explicitly binds to
  the safeguard, reports a passing outcome, predates the test period by at most
  366 days, and was collected by the assessment cutoff. A reviewer must still
  assess whether the design addresses the risk and inspect the underlying source.
- **Sample pass:** each observed asset has enough valid observations in every
  cadence window, and there are no observed deviations or unknown outcomes in the
  period. Sample ranking uses SHA-256 over the plan digest and event ID, making
  selection reproducible. All observed failures remain visible even if unselected.
- **Sample fail:** at least one observed in-period outcome failed.
- **Insufficient evidence:** missing windows, unbound observations, missing design
  documents, unknown outcomes, or invalid collection times prevent support.

Windows are half-open `[start, end)`. Design evidence cannot also serve as
operating evidence. Assessment periods must be closed, no longer than 366 days,
and not in the future. Plans are bounded to 50 controls, 100 samples per window,
and 50,000 asset/window cells per control. The implementation indexes events once;
these bounds are protective limits, not measured production capacity.

Every conclusion remains `pending_human_review`. A machine-generated workpaper is
not an audit opinion. Observed-population sampling does not establish inventory
completeness, statistical confidence, or continuous effectiveness between
observations. The plan and results carry canonical hashes and the generation
identity so reviewers can reproduce the selection and inspect evidence lineage.
