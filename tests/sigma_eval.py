"""
Minimal Sigma rule evaluator for unit-testing detections against sample events.

This is intentionally small: it supports the subset of the Sigma spec used by the
rules in this repo (plain equality, and the |contains / |startswith / |endswith
field modifiers, value lists as OR, multiple fields as AND within a block, and
a `condition:` expression that combines named detection blocks with
and / or / not / parentheses, e.g. `selection and not filter`). Validation/
compilation of the full spec is handled separately by `sigma check` (pySigma)
in CI; this module answers a different question: "given these events, does
the rule actually fire?"
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

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


def _match_block(block: Any, flat: Dict[str, Any]) -> bool:
    # A list of maps is a logical OR of sub-blocks; a map is a logical AND of fields.
    if isinstance(block, list):
        return any(_match_block(item, flat) for item in block)
    return all(_match_field(flat, field, expected) for field, expected in block.items())


_COND_TOKEN_RE = re.compile(r"\(|\)|\bnot\b|\band\b|\bor\b|[^\s()]+")


def _tokenize_condition(condition: str) -> List[str]:
    return _COND_TOKEN_RE.findall(condition)


class _ConditionParser:
    """Recursive-descent parser for `and` / `or` / `not` / `()` over named blocks."""

    def __init__(self, tokens: List[str], block_results: Dict[str, bool]):
        self.toks = tokens
        self.i = 0
        self.block_results = block_results

    def _peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def parse(self) -> bool:
        result = self._or()
        if self.i != len(self.toks):
            raise ValueError(f"Unexpected trailing tokens in condition: {self.toks[self.i:]}")
        return result

    def _or(self) -> bool:
        result = self._and()
        while self._peek() == "or":
            self.i += 1
            result = self._and() or result
        return result

    def _and(self) -> bool:
        result = self._not()
        while self._peek() == "and":
            self.i += 1
            result = self._not() and result
        return result

    def _not(self) -> bool:
        if self._peek() == "not":
            self.i += 1
            return not self._not()
        return self._primary()

    def _primary(self) -> bool:
        tok = self._peek()
        if tok == "(":
            self.i += 1
            result = self._or()
            if self._peek() != ")":
                raise ValueError("Expected ')' in condition")
            self.i += 1
            return result
        if tok is None:
            raise ValueError("Unexpected end of condition")
        if tok not in self.block_results:
            raise ValueError(f"Condition references unknown detection block: {tok!r}")
        self.i += 1
        return self.block_results[tok]


def event_matches(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Return True if `event` triggers `rule`."""
    detection = rule["detection"]
    condition = detection.get("condition", "selection")
    flat = _flatten(event)
    block_results = {
        name: _match_block(block, flat) for name, block in detection.items() if name != "condition"
    }
    tokens = _tokenize_condition(condition)
    return _ConditionParser(tokens, block_results).parse()


def load_rule(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
