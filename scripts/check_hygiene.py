"""
Detection-hygiene CI gate.

Fails the build if any shipped rule (Sigma in rules/, or Elastic TOML in
rules_toml/) is missing required metadata, or lacks its true-positive /
true-negative sample fixtures under tests/samples*/. This is what makes
"every rule is documented and tested" an enforced property instead of a
hope.
"""
from __future__ import annotations

import glob
import os
import re
import sys

import yaml

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)


def _has_attack_technique_tag(tags: list) -> bool:
    return any(TECHNIQUE_RE.match(str(t)) for t in tags or [])


def _check_fixtures(stem: str, samples_dir: str, errors: list[str]) -> None:
    sample_dir = os.path.join(REPO_ROOT, samples_dir, stem)
    for kind in ("positive", "negative"):
        path = os.path.join(sample_dir, f"{kind}.json")
        if not os.path.isfile(path):
            errors.append(f"{stem}: missing {samples_dir}/{stem}/{kind}.json")


def check_sigma_rules() -> list[str]:
    errors: list[str] = []
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, "rules", "*.yml"))):
        stem = os.path.splitext(os.path.basename(path))[0]
        with open(path, "r", encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)

        if not rule.get("author"):
            errors.append(f"{stem}: missing author")
        if not rule.get("references"):
            errors.append(f"{stem}: missing references")
        if not rule.get("level"):
            errors.append(f"{stem}: missing level")
        if not _has_attack_technique_tag(rule.get("tags")):
            errors.append(f"{stem}: missing ATT&CK technique tag (attack.tXXXX)")

        _check_fixtures(stem, "tests/samples", errors)
    return errors


def check_toml_rules() -> list[str]:
    errors: list[str] = []
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, "rules_toml", "*.toml"))):
        stem = os.path.splitext(os.path.basename(path))[0]
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        rule = data.get("rule", {})

        if not rule.get("author"):
            errors.append(f"{stem}: missing rule.author")
        if not rule.get("references"):
            errors.append(f"{stem}: missing rule.references")
        if not rule.get("severity"):
            errors.append(f"{stem}: missing rule.severity")
        if not rule.get("threat"):
            errors.append(f"{stem}: missing rule.threat (ATT&CK mapping)")

        _check_fixtures(stem, "tests/samples_toml", errors)
    return errors


def main() -> int:
    errors = check_sigma_rules() + check_toml_rules()
    if errors:
        print("DETECTION HYGIENE CHECK FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("All rules carry required metadata and test fixtures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
