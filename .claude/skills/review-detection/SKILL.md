---
name: review-detection
description: >
  Review a detection rule or detection PR in this detection-as-code repo for
  quality before it merges. Use when asked to review, critique, or sanity-check a
  Sigma rule, an Elastic TOML rule, or a pull request that adds/changes
  detections. Checks schema, ATT&CK mapping, sample coverage, false-positive
  realism, evaluator-subset compliance, and Sigma/TOML agreement.
  Triggers: "review this rule", "review the PR", "is this detection any good",
  "check my detection".
---

# Review a detection

Goal: decide whether a rule is correct, tightly scoped, and properly tested —
not just whether CI is green. CI proves the syntax is valid and the samples
pass; it does NOT prove the samples are *good*. That judgment is the review.

First, run the gates and read the diff:

```bash
sigma check rules/
python tests/validate_toml.py
pytest -v
git diff --stat && git diff
```

Then work the checklist. Report findings grouped as **Blocking** (must fix
before merge) and **Suggestions** (nice to have).

## 1. Rule logic & scope

- Does the detection actually match the behavior in the description? Read the
  query against the positive samples by hand, not just via the test.
- Is it too broad (will page on benign activity) or too narrow (trivially
  evaded by a flag reorder, casing, or quoting change)? Note bypasses.
- For Sigma: matching in `sigma_eval.py` is case-**sensitive**; for TOML KQL in
  `kql_eval.py` it is case-**insensitive**. Flag rules whose correctness
  silently depends on casing the source logs won't guarantee.

## 2. Sample coverage (the most common weakness)

- `positive.json` and `negative.json` both present and non-empty for each rule
  format. Missing samples = blocking.
- **Negatives must probe the boundary.** Look for the near-miss that separates
  signal from noise (same action, non-root identity; benign PowerShell without
  `-enc`; the legitimate admin path). If negatives are only unrelated events,
  the rule's tightness is untested — call it out.
- Positives should cover the real variants the description claims (e.g. both
  `-enc` and `-EncodedCommand`), not a single happy path.
- Field shapes match the format: Sigma samples use source field names, TOML
  samples use ECS dotted names.

## 3. Evaluator-subset compliance

A rule can pass `sigma check` yet have no runnable unit test if it uses syntax
the minimal evaluators don't support. Confirm the rule stays in-subset, or that
its absence of a unit test is intentional and noted.

- Sigma supported: single `selection` block, `condition: selection`, modifiers
  `|contains` / `|startswith` / `|endswith`, list = OR, fields = AND.
- KQL supported: `field : "value"`, `*wildcards*`, `(... or ...)` value groups,
  `and` / `or` / `not`, parentheses, dotted ECS fields.

## 4. Metadata & ATT&CK

- TOML: `rule_id` is a valid UUID and unique; `severity`, `type`, `language`
  from the allowed sets; `risk_score` an integer 0–100.
- ATT&CK tactic/technique/subtechnique IDs are real and internally consistent
  (the tactic actually contains the technique; the subtechnique belongs to the
  technique). Verify the reference URLs resolve to those IDs.
- Sigma `tags` (`attack.<tactic>`, `attack.t<id>`) agree with the TOML threat
  mapping for the same detection.

## 5. Sigma ↔ TOML agreement

When a detection ships in both formats, the two should encode the *same* logic
and the *same* ATT&CK mapping. Diff them mentally: a condition present in one
but not the other is a bug in one of them.

## 6. Hygiene

- `references` point at the technique and any primary source.
- `falsepositives` / `false_positives` are honest and specific, not "none".
- README "Current detections" table updated for new rules.
- `title` / `name` match across formats and describe the behavior, not the tool.

## Output

Give a short verdict (approve / approve-with-nits / request-changes), then the
Blocking and Suggestions lists with file:line-level specifics the author can act
on directly.
