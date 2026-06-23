"""
Minimal KQL (Kibana Query Language) evaluator for unit-testing Elastic TOML
detection rules against ECS sample events.

Supported subset (everything the rules in rules_toml/ use):
  - field : "value"                      exact match (case-insensitive)
  - field : "*substr*"                   wildcard match (* -> .*)
  - field : ("a" or "b")                 value group (OR within one field)
  - <expr> and <expr> / <expr> or <expr> boolean composition
  - not <expr>                           negation
  - ( <expr> )                           grouping

Nested ECS fields (process.command_line, aws.cloudtrail.user_identity.type) are
resolved by flattening the event to dotted keys. This is deliberately small;
its job is to answer "does this rule fire on this event?", not to be a complete
KQL engine.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


# --------------------------------------------------------------------------- #
# Tokenizer
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(
    r"""
      \s+                         # whitespace (skipped)
    | (?P<LPAREN>\()
    | (?P<RPAREN>\))
    | (?P<COLON>:)
    | "(?P<QUOTED>(?:[^"\\]|\\.)*)"
    | (?P<WORD>[^\s():"]+)
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ValueError(f"Cannot tokenize KQL near: {text[pos:pos+20]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind is None:  # whitespace
            continue
        tokens.append((kind, m.group(kind)))
    return tokens


# --------------------------------------------------------------------------- #
# AST
# --------------------------------------------------------------------------- #
class Node:
    def evaluate(self, event: Dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError


class And(Node):
    def __init__(self, l: Node, r: Node): self.l, self.r = l, r
    def evaluate(self, e): return self.l.evaluate(e) and self.r.evaluate(e)


class Or(Node):
    def __init__(self, l: Node, r: Node): self.l, self.r = l, r
    def evaluate(self, e): return self.l.evaluate(e) or self.r.evaluate(e)


class Not(Node):
    def __init__(self, c: Node): self.c = c
    def evaluate(self, e): return not self.c.evaluate(e)


class Field(Node):
    def __init__(self, field: str, values: List[str]):
        self.field, self.values = field, values

    def evaluate(self, e):
        actual = _flatten(e).get(self.field)
        if actual is None:
            return False
        return any(_match(str(actual), v) for v in self.values)


def _match(actual: str, pattern: str) -> bool:
    if "*" in pattern:
        regex = ".*".join(re.escape(part) for part in pattern.split("*"))
        return re.fullmatch(regex, actual, flags=re.IGNORECASE) is not None
    return actual.lower() == pattern.lower()


def _flatten(event: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for k, v in event.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flat.update(_flatten(v, prefix=f"{key}."))
        else:
            flat[key] = v
    return flat


# --------------------------------------------------------------------------- #
# Recursive-descent parser
# --------------------------------------------------------------------------- #
class _Parser:
    def __init__(self, tokens: List[Tuple[str, str]]):
        self.toks = tokens
        self.i = 0

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def _next(self):
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def _is_kw(self, word: str) -> bool:
        kind, val = self._peek()
        return kind == "WORD" and val.lower() == word

    def parse(self) -> Node:
        node = self._or()
        if self.i != len(self.toks):
            raise ValueError(f"Unexpected trailing tokens: {self.toks[self.i:]}")
        return node

    def _or(self) -> Node:
        node = self._and()
        while self._is_kw("or"):
            self._next()
            node = Or(node, self._and())
        return node

    def _and(self) -> Node:
        node = self._not()
        while self._is_kw("and"):
            self._next()
            node = And(node, self._not())
        return node

    def _not(self) -> Node:
        if self._is_kw("not"):
            self._next()
            return Not(self._not())
        return self._primary()

    def _primary(self) -> Node:
        kind, val = self._peek()
        if kind == "LPAREN":
            self._next()
            node = self._or()
            if self._peek()[0] != "RPAREN":
                raise ValueError("Expected ')'")
            self._next()
            return node
        # field match: WORD COLON value-or-group
        if kind != "WORD":
            raise ValueError(f"Expected field name, got {kind} {val!r}")
        field = self._next()[1]
        if self._peek()[0] != "COLON":
            raise ValueError(f"Expected ':' after field {field!r}")
        self._next()
        return Field(field, self._value_group())

    def _value_group(self) -> List[str]:
        kind, _ = self._peek()
        if kind == "LPAREN":
            self._next()
            values = [self._value()]
            while self._is_kw("or"):
                self._next()
                values.append(self._value())
            if self._peek()[0] != "RPAREN":
                raise ValueError("Expected ')' to close value group")
            self._next()
            return values
        return [self._value()]

    def _value(self) -> str:
        kind, val = self._peek()
        if kind not in ("QUOTED", "WORD"):
            raise ValueError(f"Expected value, got {kind} {val!r}")
        self._next()
        return val


def compile_kql(query: str) -> Node:
    return _Parser(_tokenize(query.strip())).parse()


def query_matches(query: str, event: Dict[str, Any]) -> bool:
    return compile_kql(query).evaluate(event)
