"""
Minimal Sigma rule evaluator for unit-testing detections against sample events.

This is intentionally small: it supports the subset of the Sigma spec used by the
rules in this repo (plain equality, and the |contains / |startswith / |endswith
field modifiers, value lists as OR, multiple fields as AND, and a single-named
`condition: selection`). Validation/compilation of the full spec is handled
separately by `sigma check` (pySigma) in CI; this module answers a different
question: "given these events, does the rule actually fire?"
"""
from __future__ import annotations

from typing import Any, Dict, List

import yaml


def _flatten(event: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flatten a nested dict into dotted keys, e.g. {'userIdentity.type': 'Root'}."""
    flat: Dict[str, Any] = {}
    for key, value in event.items():
        full = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, prefix=f"{full}."))
        else:
            flat[full] = value
    return flat


def _match_value(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier is None:
        return a == e
    if modifier == "contains":
        return e in a
    if modifier == "startswith":
        return a.startswith(e)
    if modifier == "endswith":
        return a.endswith(e)
    raise ValueError(f"Unsupported field modifier: {modifier}")


def _match_field(flat_event: Dict[str, Any], field_spec: str, expected: Any) -> bool:
    if "|" in field_spec:
        field, modifier = field_spec.split("|", 1)
    else:
        field, modifier = field_spec, None
    actual = flat_event.get(field)
    # A list of expected values is treated as a logical OR.
    expected_values = expected if isinstance(expected, list) else [expected]
    return any(_match_value(actual, ev, modifier) for ev in expected_values)


def event_matches(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Return True if `event` triggers `rule`."""
    detection = rule["detection"]
    condition = detection.get("condition", "selection")
    if condition != "selection":
        raise NotImplementedError(
            f"sigma_eval only supports `condition: selection` (got: {condition!r})"
        )
    selection = detection["selection"]
    flat = _flatten(event)
    # All fields within a selection must match (logical AND).
    return all(_match_field(flat, field, expected) for field, expected in selection.items())


def load_rule(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
