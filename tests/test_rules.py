"""
Detection unit tests.

For every rule in rules/ we expect a samples directory named after the rule
filename stem, containing positive.json (events that MUST fire) and
negative.json (events that MUST NOT fire). This guarantees each shipped rule
has true-positive coverage and is checked for the obvious false positives.
"""
import json
import os
import glob

import pytest

from sigma_eval import load_rule, event_matches

HERE = os.path.dirname(__file__)
REPO = os.path.dirname(HERE)
RULES = sorted(glob.glob(os.path.join(REPO, "rules", "*.yml")))
SAMPLES = os.path.join(HERE, "samples")


def _stem(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def _load_events(rule_path: str, kind: str):
    path = os.path.join(SAMPLES, _stem(rule_path), f"{kind}.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize("rule_path", RULES, ids=_stem)
def test_rule_has_sample_dir(rule_path):
    assert os.path.isdir(os.path.join(SAMPLES, _stem(rule_path))), (
        f"Missing samples/ directory for rule '{_stem(rule_path)}'"
    )


@pytest.mark.parametrize("rule_path", RULES, ids=_stem)
def test_true_positives_fire(rule_path):
    rule = load_rule(rule_path)
    events = _load_events(rule_path, "positive")
    assert events, "Expected at least one true-positive sample event"
    for i, event in enumerate(events):
        assert event_matches(rule, event), (
            f"True-positive event #{i} did NOT fire rule '{_stem(rule_path)}'"
        )


@pytest.mark.parametrize("rule_path", RULES, ids=_stem)
def test_true_negatives_do_not_fire(rule_path):
    rule = load_rule(rule_path)
    events = _load_events(rule_path, "negative")
    assert events, "Expected at least one true-negative sample event"
    for i, event in enumerate(events):
        assert not event_matches(rule, event), (
            f"True-negative event #{i} incorrectly fired rule '{_stem(rule_path)}'"
        )
