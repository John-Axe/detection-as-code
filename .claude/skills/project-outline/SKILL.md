---
name: project-outline
description: >
  Produce a structured orientation overview of this detection-as-code repo for a
  new contributor or for an agent picking up work. Use when someone asks "how is
  this project laid out", "give me an overview / outline of the repo", "onboard
  me", "what does each part do", or "where do I put X". Reads the live tree so the
  outline reflects the repo's current state, not a stale snapshot.
---

# Project outline

Generate an accurate, current map of the repo. Do NOT recite from memory — read
the tree and the key files first, then write the outline so it reflects what is
actually on disk right now.

## Step 1 — Read the current state

```bash
# structure (skip noise)
find . -type f -not -path './.git/*' | sort
# what detections currently exist
ls rules rules_toml
ls tests/samples tests/samples_toml
# the source of truth for the workflow
sed -n '1,200p' README.md
```

Also open `.github/workflows/ci.yml`, `requirements.txt`, and `pytest.ini` so the
outline names the real CI gates and entry points.

## Step 2 — Write the outline

Cover these sections, kept tight and concrete:

1. **What this repo is** — detection-as-code: SIEM rules managed like software,
   version-controlled, peer-reviewed via PR, validated and unit-tested in CI
   before merge.

2. **The two rule formats, side by side**
   - `rules/*.yml` — Sigma, vendor-neutral YAML; converts to many SIEMs.
   - `rules_toml/*.toml` — Elastic detection-rules TOML; ECS fields, KQL,
     ATT&CK threat mapping.

3. **Directory map** (regenerate from the live tree; example shape):
   - `rules/` — Sigma rules.
   - `rules_toml/` — Elastic TOML rules.
   - `tests/sigma_eval.py` — minimal Sigma evaluator (does the rule fire?).
   - `tests/kql_eval.py` — minimal KQL evaluator for TOML rules.
   - `tests/validate_toml.py` — TOML schema + ATT&CK validator (CI gate).
   - `tests/test_rules.py` / `tests/test_toml_rules.py` — pytest over every rule.
   - `tests/samples/<stem>/` and `tests/samples_toml/<stem>/` —
     `positive.json` / `negative.json` per rule.
   - `.github/workflows/ci.yml` — validate + test on every push/PR.

4. **The CI gates** (a red check blocks merge):
   `sigma check rules/` → `python tests/validate_toml.py` → `pytest -v`.

5. **Current detections** — list them from `rules/` + `rules_toml/` with their
   ATT&CK technique and level (cross-check the README table; flag drift if the
   table and the files disagree).

6. **Where things go** — adding a detection touches a rule file, a samples dir
   per format, and the README table. (Point to the `add-detection` skill.)

7. **Local commands**
   ```bash
   pip install -r requirements.txt
   sigma check rules/
   python tests/validate_toml.py
   pytest -v
   ```

## Step 3 — Note any drift

If the README's "Current detections" table, the files in `rules*/`, and the
sample directories disagree (a rule with no samples, a sample dir with no rule,
a table row with no file), surface it explicitly — that gap is usually the most
useful thing in the outline.

## Output

Default to a concise prose+list briefing in chat. If asked for a deliverable,
write it to `docs/PROJECT_OUTLINE.md` (a non-protected path) rather than editing
README.md.
