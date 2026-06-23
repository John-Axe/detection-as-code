"""
Detection unit tests for the Elastic-style TOML rules.

For every rule in rules_toml/ we expect a samples directory under
tests/samples_toml/<rule-stem>/ with positive.json (events that MUST fire) and
negative.json (events that MUST NOT fire). The rule's KQL query is evaluated
against each event with the minimal kql_eval engine.
"""
import glob
import json
import os

import pytest

from kql_eval import query_matches

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

HERE = os.path.dirname(__file__)
REPO = os.path.dirname(HERE)
RULES = sorted(glob.glob(os.path.join(REPO, "rules_toml", "*.toml")))
SAMPLES = os.path.join(HERE, "samples_toml")


def _stem(path):
    return os.path.splitext(os.path.basename(path))[0]


def _query(rule_path):
    with open(rule_path, "rb") as fh:
        return tomllib.load(fh)["rule"]["query"]


def _events(rule_path, kind):
    with open(os.path.join(SAMPLES, _stem(rule_path), f"{kind}.json"), encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize("rule_path", RULES, ids=_stem)
def test_true_positives_fire(rule_path):
    q = _query(rule_path)
    events = _events(rule_path, "positive")
    assert events
    for i, ev in enumerate(events):
        assert query_matches(q, ev), f"TP event #{i} did NOT fire '{_stem(rule_path)}'"


@pytest.mark.parametrize("rule_path", RULES, ids=_stem)
def test_true_negatives_do_not_fire(rule_path):
    q = _query(rule_path)
    events = _events(rule_path, "negative")
    assert events
    for i, ev in enumerate(events):
        assert not query_matches(q, ev), f"TN event #{i} incorrectly fired '{_stem(rule_path)}'"
