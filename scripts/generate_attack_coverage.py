"""
Generate MITRE ATT&CK coverage artifacts from the Sigma rules in rules/.

Reads every rule's `tags:` list, pulls out ATT&CK technique IDs
(attack.tXXXX or attack.tXXXX.YYY) and tactic shortnames (e.g.
attack.initial-access), and writes:

  - docs/attack/layer.json       ATT&CK Navigator layer (importable at
                                  https://mitre-attack.github.io/attack-navigator/)
  - docs/ATTACK_COVERAGE.md      Markdown tactic/technique coverage matrix

Run as a script; exits non-zero if a rule has no ATT&CK technique tag, so it
can also act as a CI gate for tag presence.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "rules")
LAYER_PATH = os.path.join(REPO_ROOT, "docs", "attack", "layer.json")
MATRIX_PATH = os.path.join(REPO_ROOT, "docs", "ATTACK_COVERAGE.md")
README_PATH = os.path.join(REPO_ROOT, "README.md")

README_MATRIX_START = "<!-- ATTACK_COVERAGE_START -->"
README_MATRIX_END = "<!-- ATTACK_COVERAGE_END -->"
README_BADGE_RE = re.compile(
    r"(https://img\.shields\.io/badge/ATT%26CK%20techniques-)\d+(-blue)"
)

TECHNIQUE_RE = re.compile(r"^attack\.t(\d{4})(\.\d{3})?$", re.IGNORECASE)

# MITRE ATT&CK Enterprise tactics in kill-chain order: shortname -> display name.
TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
TACTIC_NAMES = dict(TACTIC_ORDER)

# Display names for the technique IDs currently in use. Extend as new
# techniques are tagged; an unknown ID still renders, just without a name.
TECHNIQUE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1078": "Valid Accounts",
    "T1078.004": "Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Additional Cloud Credentials",
}


def load_rules() -> list[dict]:
    rules = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        data["_path"] = path
        data["_stem"] = os.path.splitext(os.path.basename(path))[0]
        rules.append(data)
    return rules


def extract_attack_tags(rule: dict) -> tuple[set[str], set[str]]:
    """Return (technique_ids, tactic_shortnames) found in a rule's tags."""
    techniques: set[str] = set()
    tactics: set[str] = set()
    for tag in rule.get("tags") or []:
        tag = str(tag)
        m = TECHNIQUE_RE.match(tag)
        if m:
            tech_id = "T" + m.group(1) + (m.group(2) or "")
            techniques.add(tech_id)
            continue
        if tag.startswith("attack."):
            shortname = tag[len("attack."):]
            if shortname in TACTIC_NAMES:
                tactics.add(shortname)
    return techniques, tactics


def build_coverage(rules: list[dict]) -> dict[str, dict]:
    """technique_id -> {tactics: set[str], rules: list[str]}"""
    coverage: dict[str, dict] = {}
    missing = []
    for rule in rules:
        techniques, tactics = extract_attack_tags(rule)
        if not techniques:
            missing.append(rule["_stem"])
            continue
        for tech_id in techniques:
            entry = coverage.setdefault(tech_id, {"tactics": set(), "rules": []})
            entry["tactics"] |= tactics
            entry["rules"].append(rule["_stem"])
    if missing:
        raise SystemExit(
            "Rules missing ATT&CK technique tags (attack.tXXXX): "
            + ", ".join(sorted(missing))
        )
    return coverage


def render_layer(coverage: dict[str, dict]) -> dict:
    techniques = []
    for tech_id, entry in sorted(coverage.items()):
        tactics = sorted(entry["tactics"]) or ["unattributed"]
        for tactic in tactics:
            techniques.append(
                {
                    "techniqueID": tech_id,
                    "tactic": tactic,
                    "score": len(entry["rules"]),
                    "color": "",
                    "comment": "Covered by: " + ", ".join(sorted(entry["rules"])),
                    "enabled": True,
                    "metadata": [],
                    "showSubtechniques": False,
                }
            )
    return {
        "name": "Detection-as-Code ATT&CK Coverage",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from rules/*.yml ATT&CK tags. Do not edit by hand.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": max((len(e["rules"]) for e in coverage.values()), default=1),
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "sorting": 0,
    }


def render_matrix(coverage: dict[str, dict], rule_count: int) -> str:
    lines = [
        "# MITRE ATT&CK Coverage Matrix",
        "",
        "Auto-generated by `scripts/generate_attack_coverage.py` from the ATT&CK",
        "tags on every rule in `rules/`. Do not edit by hand.",
        "",
        f"**{len(coverage)}** technique(s) covered across **{rule_count}** rule(s).",
        "",
        "| Tactic | Technique | Name | Rules |",
        "|--------|-----------|------|-------|",
    ]
    for shortname, tactic_name in TACTIC_ORDER:
        techs = sorted(
            tech_id for tech_id, entry in coverage.items() if shortname in entry["tactics"]
        )
        for tech_id in techs:
            entry = coverage[tech_id]
            name = TECHNIQUE_NAMES.get(tech_id, "")
            rules_list = ", ".join(sorted(entry["rules"]))
            lines.append(f"| {tactic_name} | {tech_id} | {name} | {rules_list} |")
    lines.append("")
    return "\n".join(lines)


def render_readme_table(coverage: dict[str, dict]) -> str:
    lines = ["| Tactic | Technique | Name | Rules |", "|--------|-----------|------|-------|"]
    for shortname, tactic_name in TACTIC_ORDER:
        for tech_id in sorted(
            tech_id for tech_id, entry in coverage.items() if shortname in entry["tactics"]
        ):
            entry = coverage[tech_id]
            name = TECHNIQUE_NAMES.get(tech_id, "")
            rules_list = ", ".join(sorted(entry["rules"]))
            lines.append(f"| {tactic_name} | {tech_id} | {name} | {rules_list} |")
    return "\n".join(lines)


def update_readme(coverage: dict[str, dict]) -> None:
    if not os.path.isfile(README_PATH):
        return
    with open(README_PATH, "r", encoding="utf-8") as fh:
        readme = fh.read()

    if README_MATRIX_START in readme and README_MATRIX_END in readme:
        pre, _, rest = readme.partition(README_MATRIX_START)
        _, _, post = rest.partition(README_MATRIX_END)
        table = render_readme_table(coverage)
        readme = f"{pre}{README_MATRIX_START}\n{table}\n{README_MATRIX_END}{post}"

    readme = README_BADGE_RE.sub(rf"\g<1>{len(coverage)}\g<2>", readme)

    with open(README_PATH, "w", encoding="utf-8") as fh:
        fh.write(readme)


def main() -> int:
    rules = load_rules()
    coverage = build_coverage(rules)

    os.makedirs(os.path.dirname(LAYER_PATH), exist_ok=True)
    with open(LAYER_PATH, "w", encoding="utf-8") as fh:
        json.dump(render_layer(coverage), fh, indent=2)
        fh.write("\n")

    with open(MATRIX_PATH, "w", encoding="utf-8") as fh:
        fh.write(render_matrix(coverage, len(rules)))

    update_readme(coverage)

    print(f"Wrote {LAYER_PATH}")
    print(f"Wrote {MATRIX_PATH}")
    print(f"Updated ATT&CK coverage table + badge in {README_PATH}")
    print(f"Covered {len(coverage)} technique(s) across {len(rules)} rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
