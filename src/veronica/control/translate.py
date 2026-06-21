"""NL -> {primitive_id, params}, schema-validated against the catalog.

This is the only place free-form natural language enters the control plane. The
LLM returns structured JSON naming a catalog primitive and its params; we reject
anything that names an unknown primitive or whose params fail that primitive's
JSON Schema. No free-form kernel path exists — the output is catalog-bounded.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

import jsonschema

from veronica.control.client import Primitive

_SYSTEM = (
    "You translate a natural-language policy request into exactly one vetted "
    "kernel primitive. Respond with ONLY a JSON object of the form "
    '{"primitive_id": "<one of the catalog ids>", "params": {...}}. '
    "Choose params that satisfy the chosen primitive's JSON Schema. No prose."
)


class LLM(Protocol):
    """A minimal, mockable structured-output LLM."""

    def complete(self, system: str, user: str) -> str: ...


class TranslationError(Exception):
    """Raised when the LLM picks an unknown primitive or invalid params."""


def translate(
    nl: str, primitives: list[Any], llm: LLM
) -> tuple[str, dict[str, Any]]:
    schemas = _schemas(primitives)
    user = _prompt(nl, primitives)
    raw = llm.complete(_SYSTEM, user)

    decision = _load(raw)
    primitive_id = decision.get("primitive_id")
    params = decision.get("params", {})

    schema = schemas.get(primitive_id)
    if schema is None:
        raise TranslationError(f"unknown primitive id: {primitive_id!r}")

    _validate(schema, params)
    return primitive_id, params


def _schemas(primitives: list[Any]) -> dict[str, dict[str, Any]]:
    return {_id(p): _params(p) for p in primitives}


def _prompt(nl: str, primitives: list[Any]) -> str:
    catalog = [
        {"id": _id(p), "desc": _desc(p), "params": _params(p)} for p in primitives
    ]
    return (
        f"Request: {nl}\n\n"
        f"Catalog (pick one id and emit schema-valid params):\n"
        f"{json.dumps(catalog, indent=2)}"
    )


def _load(raw: str) -> dict[str, Any]:
    decision = _decode(raw)
    if not isinstance(decision, dict) or "primitive_id" not in decision:
        raise TranslationError(f"LLM output is not a valid decision object: {raw!r}")
    return decision


def _decode(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TranslationError(f"LLM output is not valid JSON: {raw!r}") from exc


def _validate(schema: dict[str, Any], params: dict[str, Any]) -> None:
    error = next(iter(jsonschema.Draft202012Validator(schema).iter_errors(params)), None)
    if error is not None:
        raise TranslationError(f"params failed schema: {error.message}")


# Primitive accessors — accept dicts (from serialized list_primitives) or
# Primitive instances interchangeably.

def _id(p: Any) -> str:
    return p.id if isinstance(p, Primitive) else p["id"]


def _desc(p: Any) -> str:
    return p.desc if isinstance(p, Primitive) else p.get("desc", "")


def _params(p: Any) -> dict[str, Any]:
    return p.params if isinstance(p, Primitive) else p["params"]
