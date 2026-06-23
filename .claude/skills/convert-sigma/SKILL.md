---
name: convert-sigma
description: >
  Convert a Sigma rule in this repo into a SIEM-native query (Elasticsearch
  Lucene/ES|QL, Splunk SPL, Microsoft Sentinel KQL, and others) using the pySigma
  / sigma-cli backends. Use when someone wants to deploy, export, translate, or
  "get the Splunk/Elastic/Sentinel query for" a rule under rules/.
  Triggers: "convert this Sigma rule", "export to Splunk", "Lucene query for
  <rule>", "translate the rule to Sentinel".
---

# Convert a Sigma rule to a SIEM query

`sigma convert` (from `sigma-cli`, already a repo dependency) compiles a Sigma
rule into a target SIEM's query language using a pluggable backend. The backend
for your target SIEM is a separate pip package that must be installed first.

## Step 1 — Pick the target and install its backend

| Target SIEM | pip package | example `-t` target |
|---|---|---|
| Elasticsearch (Lucene / ES\|QL / EQL) | `pysigma-backend-elasticsearch` | `lucene`, `esql`, `eql` |
| Splunk | `pysigma-backend-splunk` | `splunk` |
| Microsoft Sentinel / Defender (KQL) | `pysigma-backend-microsoft365defender` or `pysigma-backend-kusto` | `kusto` |
| QRadar | `pysigma-backend-qradar-aql` | `qradar` |

```bash
pip install pysigma-backend-elasticsearch   # example: Elastic
sigma list targets                          # confirm the backend registered
sigma list formats <target>                 # output formats a backend offers
```

## Step 2 — Convert

```bash
# Single rule to Elastic Lucene
sigma convert -t lucene rules/windows_powershell_encodedcommand.yml

# Whole rules/ directory to Splunk SPL
sigma convert -t splunk rules/

# A specific output format (e.g. a deployable Elastic rule, Kibana ndjson, etc.)
sigma convert -t lucene -f <format> rules/<stem>.yml
```

Optional refinements:

- **Pipelines** map generic Sigma fields to a SIEM's schema (e.g. ECS):
  `sigma convert -t lucene -p ecs_windows rules/<stem>.yml`. List available
  pipelines with `sigma list pipelines`. Use the pipeline that matches the index
  this rule will run against.
- **Output to a file** for review or deployment:
  `sigma convert -t splunk rules/<stem>.yml -o out.spl`.

## Step 3 — Sanity-check the output

- The converted query should reproduce the rule's intent — verify the field
  names and the AND/OR structure survived the pipeline mapping.
- Cross-check against this repo's hand-written TOML KQL for the same detection
  (in `rules_toml/`) when one exists; large divergence usually means a wrong or
  missing field-mapping pipeline.
- Conversion does not run the unit tests. Logic is still owned by `pytest` over
  the sample events — convert for deployment, not as a correctness check.

## Notes

- Backends are versioned independently of `sigma-cli`; if `sigma convert` errors
  about an unknown target, the backend isn't installed or didn't register —
  re-check `sigma list targets`.
- If a rule uses Sigma syntax a backend can't express, the CLI reports it. Either
  adjust the rule or pick a backend/pipeline that supports the construct.
- These backend packages are install-on-demand and intentionally NOT pinned in
  `requirements.txt` (which only needs `sigma-cli` for `sigma check`). Don't add
  them there unless the team standardizes on one target.
