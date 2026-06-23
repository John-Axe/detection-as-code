# Detection-as-Code

[![detection-ci](https://github.com/YOUR_GITHUB_USERNAME/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/detection-as-code/actions/workflows/ci.yml)

Manage SIEM detections like software: every rule is version-controlled, reviewed
via pull request, automatically validated, and **unit-tested against sample logs
before it can merge**. No more shipping a broken rule to production and finding
out it doesn't fire during an incident.

This repo carries detections in **two formats side by side**:

- **Sigma** (`rules/`) — vendor-neutral YAML that converts to Elastic, Splunk,
  Sentinel, and others.
- **Elastic detection-rules TOML** (`rules_toml/`) — the native format of the
  [elastic/detection-rules](https://github.com/elastic/detection-rules) project,
  with ECS field names, ATT&CK threat mapping, and KQL queries.

Both halves are validated and unit-tested in CI.

## Why this exists

In a lot of teams, detection rules live in a console where they can't be diffed,
reviewed, or tested. This repo treats them as code:

- **Version control** — full history of every rule change.
- **Peer review** — changes land through PRs, not clicks in a UI.
- **Validation** — `sigma check` (pySigma) for Sigma; a schema + ATT&CK validator
  for the TOML rules.
- **Testing** — every rule ships with true-positive and true-negative sample
  events; CI proves the rule fires on the bad ones and stays silent on the good.

## How it works

```
rules/*.yml      ─► sigma check          ─┐
rules_toml/*.toml ─► validate_toml.py     ├─► must pass before merge
                                          │
pytest ─► sigma_eval  evaluates Sigma rules vs tests/samples/<rule>/{positive,negative}.json
       └► kql_eval    evaluates TOML KQL queries vs tests/samples_toml/<rule>/{positive,negative}.json
```

Every push and pull request runs all of it in GitHub Actions
(`.github/workflows/ci.yml`). A red check blocks the merge.

## Repo layout

```
rules/                         Sigma detection rules (YAML)
rules_toml/                    Elastic-style detection rules (TOML, KQL, ECS)
tests/
  sigma_eval.py                minimal Sigma evaluator
  kql_eval.py                  minimal KQL evaluator (for TOML rules)
  validate_toml.py             TOML schema + ATT&CK validator (CI gate)
  test_rules.py                tests over every Sigma rule
  test_toml_rules.py           tests over every TOML rule
  samples/<rule-stem>/         positive.json / negative.json  (Sigma)
  samples_toml/<rule-stem>/    positive.json / negative.json  (TOML, ECS fields)
.github/workflows/ci.yml       validate + test on every push/PR
```

## Current detections

| Rule | Sigma | TOML | ATT&CK | Level |
|------|:-----:|:----:|--------|-------|
| Suspicious PowerShell EncodedCommand Execution | ✓ | ✓ | T1059.001 | high |
| AWS Root Account Console Login | ✓ | ✓ | T1078.004 | high |

## Run it locally

```bash
pip install -r requirements.txt
sigma check rules/             # validate Sigma syntax + schema
python tests/validate_toml.py  # validate Elastic TOML rules
pytest -v                      # run all detection unit tests
```

## Add a new detection

1. Write the rule in `rules/your_rule.yml` (Sigma) and/or
   `rules_toml/your_rule.toml` (Elastic).
2. Add `positive.json` (events it should catch) and `negative.json` (events it
   should ignore) under the matching `tests/samples*/your_rule/` directory.
3. Run `pytest -v` until green, then open a PR.

## Convert a Sigma rule to your SIEM

```bash
pip install pysigma-backend-elasticsearch
sigma convert -t lucene rules/windows_powershell_encodedcommand.yml
```
