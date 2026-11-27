"""Tool-list filtering shared by the framework adapters."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from importlib import resources
from typing import Any

from .types import ALLOWED_TOOLS, AgentError

_FORBIDDEN = frozenset(json.loads(resources.files(__package__).joinpath("forbidden_words.json").read_text()))
_ALLOWED = frozenset(ALLOWED_TOOLS)


def _name(tool: Any) -> str:
    return tool["name"] if isinstance(tool, dict) else tool.name


def pick_allowed_tools(tools: Iterable[Any]) -> tuple[list[Any], list[str]]:
    """Keeps only ALLOWED_TOOLS; the dropped tools are reported by name only."""
    kept: list[Any] = []
    dropped: list[str] = []
    for t in tools:
        if _name(t) in _ALLOWED:
            kept.append(t)
        else:
            dropped.append(_name(t))
    return kept, dropped


def _last_word(prop: str) -> str:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", prop)) if w]
    return words[-1].lower() if words else ""


def _value_shaped(schema: Any, depth: int = 0) -> bool:
    if not isinstance(schema, dict) or depth > 16:
        return False
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            if _last_word(name) in _FORBIDDEN or _value_shaped(sub, depth + 1):
                return True
    for key in ("items", "additionalProperties", "not", "if", "then", "else"):
        if _value_shaped(schema.get(key), depth + 1):
            return True
    for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
        lst = schema.get(key)
        if isinstance(lst, list) and any(_value_shaped(x, depth + 1) for x in lst):
            return True
    for key in ("$defs", "definitions"):
        defs = schema.get(key)
        if isinstance(defs, dict) and any(_value_shaped(x, depth + 1) for x in defs.values()):
            return True
    return False


def _schema(tool: Any, *names: str) -> Any:
    for n in names:
        v = tool.get(n) if isinstance(tool, dict) else getattr(tool, n, None)
        if v is not None:
            return v
    return None


def assert_no_value_tools(tools: Iterable[Any]) -> None:
    """Raises AgentError("unsafe_tool") when a tool's input or output schema has a value-shaped property."""
    for t in tools:
        if _value_shaped(_schema(t, "inputSchema", "input_schema")) or _value_shaped(
            _schema(t, "outputSchema", "output_schema")
        ):
            raise AgentError("unsafe_tool", 0)
