---
name: add-detection
description: >
  Author a new detection end-to-end for this detection-as-code repo. Use whenever
  someone wants to add, write, or ship a new SIEM detection / rule here — Sigma
  YAML, Elastic TOML, or both. Covers writing the rule(s), creating positive and
  negative sample events, and running the validators and pytest until green.
  Triggers: "add a detection", "write a rule for <technique>", "new Sigma rule",
  "new TOML rule", "detect <attacker behavior>".
---

# Add a detection

A detection in this repo is not just a rule — it is a rule **plus** the sample
events that prove it fires on the bad and stays silent on the good. CI rejects a
rule with no samples. Always ship both halves together.

## Decide which format(s)

This repo carries detections in two formats. Match existing coverage in the
README table; when in doubt, write **both**.

- **Sigma** — `rules/<stem>.yml`, vendor-neutral. Samples in
  `tests/samples/<stem>/`.
- **Elastic TOML** — `rules_toml/<stem>.toml`, ECS field names + KQL. Samples in
  `tests/samples_toml/<stem>/`.

Pick one `<stem>` (snake_case, e.g. `okta_mfa_bombing`) and reuse it everywhere.
The Sigma and TOML stems need not be byte-identical (the repo has
`windows_powershell_encodedcommand` vs `powershell_encodedcommand`), but each
rule's samples directory **must** match that rule's own filename stem.

## Step 1 — Write the Sigma rule (`rules/<stem>.yml`)

Copy the shape of an existing rule. Required structure:

```yaml
title: <Human readable title>
id: <a fresh UUIDv4>
status: experimental
description: >
  What it detects and why it is high-signal.
references:
  - https://attack.mitre.org/techniques/Txxxx/<sub>/
author: <name>
date: <YYYY-MM-DD>
tags:
  - attack.<tactic_name>      # e.g. attack.execution
  - attack.t<technique>       # e.g. attack.t1059.001
logsource:
  product: <windows|aws|...>
  service: <cloudtrail|...>   # or: category: process_creation
detection:
  selection:
    Field: value
    Field|contains: [' substr ', ' other ']
  condition: selection
falsepositives:
  - Honest description of what could legitimately trigger it
level: <low|medium|high|critical>
```

**The local evaluator (`tests/sigma_eval.py`) only supports a subset** — stay
inside it or the unit tests cannot run:

- Exactly one selection block named `selection`, and `condition: selection`.
  No `1 of`, `all of`, `not`, multiple named blocks, or timeframes.
- Field modifiers: only `|contains`, `|startswith`, `|endswith` (and plain
  equality). Matching is exact-string and case-**sensitive**.
- A list of values under one field = OR. Multiple fields = AND.
- Nested event fields are addressed with dots: `userIdentity.type`.

(`sigma check` validates the *full* Sigma spec, so richer syntax passes lint —
but then the rule has no runnable unit test here. Prefer staying in the subset.)

## Step 2 — Write the Elastic TOML rule (`rules_toml/<stem>.toml`)

```toml
[metadata]
creation_date = "YYYY/MM/DD"
updated_date  = "YYYY/MM/DD"
maturity = "production"

[rule]
author = ["<name>"]
rule_id = "<a fresh UUIDv4, different from the Sigma id>"
name = "<title>"
description = """<what + why>"""
severity = "high"          # low | medium | high | critical
risk_score = 73            # integer 0-100
type = "query"             # query | eql | threshold | machine_learning | new_terms
language = "kuery"         # kuery | lucene | eql
index = ["logs-...-*"]
query = '''
<KQL here>
'''
references = ["https://attack.mitre.org/techniques/Txxxx/<sub>/"]
false_positives = ["..."]

[[rule.threat]]
framework = "MITRE ATT&CK"
[rule.threat.tactic]
id = "TAxxxx"
name = "<Tactic>"
reference = "https://attack.mitre.org/tactics/TAxxxx/"
[[rule.threat.technique]]
id = "Txxxx"
name = "<Technique>"
reference = "https://attack.mitre.org/techniques/Txxxx/"
[[rule.threat.technique.subtechnique]]
id = "Txxxx.0yy"
name = "<Subtechnique>"
reference = "https://attack.mitre.org/techniques/Txxxx/0yy/"
```

`validate_toml.py` enforces: all of `rule_id, name, description, severity,
risk_score, type, language, query` present; `rule_id` a valid UUID; severity /
type / language from the allowed sets above; `risk_score` an integer 0–100; and
a `rule.threat` ATT&CK mapping present.

**The KQL evaluator (`tests/kql_eval.py`) supports** (use only this):
`field : "value"` (case-**insensitive**), `field : "*substr*"` wildcards,
`field : ("a" or "b")` value groups, `and` / `or` / `not`, and parentheses.
ECS nested fields resolve via dotted keys (`process.command_line`,
`aws.cloudtrail.user_identity.type`). No ranges, comparisons, or exists checks.

## Step 3 — Write the sample events

For each format, create `positive.json` and `negative.json` (JSON arrays of
event objects) in the matching samples dir. Each file must be non-empty.

- **positive.json** — realistic events the rule MUST fire on. Mirror the field
  shape the rule reads: Sigma samples use source field names (`CommandLine`,
  `userIdentity.type`); TOML samples use ECS names (`process.command_line`,
  `aws.cloudtrail.user_identity.type`).
- **negative.json** — events the rule MUST NOT fire on. Make these **probe the
  boundary**, not just unrelated noise: the same action by a non-root identity,
  the benign PowerShell call without `-enc`, etc. A negative set of only
  obviously-unrelated events doesn't prove the rule is tight.

## Step 4 — Validate and test until green

```bash
pip install -r requirements.txt          # first time
sigma check rules/                        # Sigma syntax + schema
python tests/validate_toml.py             # TOML schema + ATT&CK
pytest -v                                 # fires-on-positive / silent-on-negative
```

If a positive doesn't fire or a negative fires, fix the rule or the sample —
do not weaken the test. Re-run until all three pass.

## Step 5 — Update the README

Add a row to the **Current detections** table in `README.md`: title, ✓ for each
format shipped, the ATT&CK technique id, and the level/severity.

## Step 6 — Hand off

Summarize: rule name, technique, formats shipped, passing test output. Changes
land via PR in this repo — remind the author to open one.
