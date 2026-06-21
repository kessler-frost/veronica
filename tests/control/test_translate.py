"""Tests for translate() — NL -> schema-validated {primitive_id, params}.

Uses a MOCK LLM (no real LM Studio). The LLM is the only place free-form text
enters; translate must reject anything outside the catalog or its schemas.
"""

from __future__ import annotations

import json

import pytest

from veronica.control.catalog import PRIMITIVES
from veronica.control.client import Primitive
from veronica.control.translate import TranslationError, translate

PRIMS = [
    {"id": p.id, "desc": p.desc, "params": p.params, "hooks": list(p.hooks)}
    for p in PRIMITIVES
]


class MockLLM:
    """Returns a canned JSON string regardless of prompt; records the call."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.reply


def _reply(primitive_id, params):
    return json.dumps({"primitive_id": primitive_id, "params": params})


def test_translate_returns_id_and_params():
    llm = MockLLM(_reply("block-mount", {"path_prefix": "/var/lib/docker/volumes"}))
    pid, params = translate("don't let docker create volumes", PRIMS, llm)
    assert pid == "block-mount"
    assert params == {"path_prefix": "/var/lib/docker/volumes"}


def test_translate_passes_catalog_to_llm():
    llm = MockLLM(_reply("block-mount", {"path_prefix": "/v"}))
    translate("block docker volumes", PRIMS, llm)
    assert llm.calls, "LLM was not called"
    _system, user = llm.calls[0]
    # The natural-language request and the catalog ids reach the LLM prompt.
    assert "block docker volumes" in user
    assert "block-mount" in user


def test_translate_unknown_primitive_id_raises():
    llm = MockLLM(_reply("totally-made-up", {"x": 1}))
    with pytest.raises(TranslationError):
        translate("do something weird", PRIMS, llm)


def test_translate_schema_invalid_params_missing_required_raises():
    # block-egress requires allow_cidrs.
    llm = MockLLM(_reply("block-egress", {}))
    with pytest.raises(TranslationError):
        translate("block docker network", PRIMS, llm)


def test_translate_schema_invalid_params_wrong_type_raises():
    # path_prefix must be a string, not a number.
    llm = MockLLM(_reply("block-mount", {"path_prefix": 42}))
    with pytest.raises(TranslationError):
        translate("block mounts", PRIMS, llm)


def test_translate_rejects_additional_properties():
    llm = MockLLM(_reply("block-mount", {"path_prefix": "/v", "bogus": True}))
    with pytest.raises(TranslationError):
        translate("block mounts with junk", PRIMS, llm)


def test_translate_rejects_non_json_llm_output():
    llm = MockLLM("this is not json at all")
    with pytest.raises(TranslationError):
        translate("anything", PRIMS, llm)


def test_translate_rejects_missing_primitive_id_field():
    llm = MockLLM(json.dumps({"params": {"path_prefix": "/v"}}))
    with pytest.raises(TranslationError):
        translate("anything", PRIMS, llm)


def test_translate_accepts_optional_params_omitted():
    # block-mount's path_prefix is optional; empty params is valid.
    llm = MockLLM(_reply("block-mount", {}))
    pid, params = translate("block all docker mounts", PRIMS, llm)
    assert pid == "block-mount"
    assert params == {}


def test_translate_accepts_primitive_objects_too():
    """translate works whether primitives are dicts or Primitive instances."""
    llm = MockLLM(_reply("block-exec", {"binaries": ["sh"]}))
    prims: list[Primitive] = list(PRIMITIVES)
    pid, params = translate("block shell exec", prims, llm)
    assert pid == "block-exec"
    assert params == {"binaries": ["sh"]}
