"""The vetted v1 enforcement-primitive catalog (host-side mirror).

This is the same fixed set the Go daemon owns (`internal/control/catalog.go`).
The warden never invents primitives; the LLM can only select one of these by id,
and its params are validated against the primitive's JSON Schema before any
policy is applied. Mirrors the design spec's primitive table.
"""

from __future__ import annotations

from veronica.control.client import Primitive

PRIMITIVES: tuple[Primitive, ...] = (
    Primitive(
        id="block-path-write",
        desc="Block writes under a path prefix",
        params={
            "type": "object",
            "properties": {"path_prefix": {"type": "string"}},
            "required": ["path_prefix"],
            "additionalProperties": False,
        },
        hooks=("path_mkdir", "inode_create", "file_open"),
    ),
    Primitive(
        id="block-mount",
        desc="Block mount / volume creation (e.g. docker volume create)",
        params={
            "type": "object",
            "properties": {"path_prefix": {"type": "string"}},
            "additionalProperties": False,
        },
        hooks=("sb_mount", "move_mount"),
    ),
    Primitive(
        id="block-egress",
        desc="Block outbound connections to non-allowed CIDRs",
        params={
            "type": "object",
            "properties": {
                "allow_cidrs": {
                    "type": "array",
                    "items": {"type": "string"},
                }
            },
            "required": ["allow_cidrs"],
            "additionalProperties": False,
        },
        hooks=("socket_connect",),
    ),
    Primitive(
        id="block-exec",
        desc="Block exec of named binaries",
        params={
            "type": "object",
            "properties": {
                "binaries": {
                    "type": "array",
                    "items": {"type": "string"},
                }
            },
            "required": ["binaries"],
            "additionalProperties": False,
        },
        hooks=("bprm_check_security",),
    ),
    Primitive(
        id="drop-capability",
        desc="Deny named capabilities",
        params={
            "type": "object",
            "properties": {
                "caps": {
                    "type": "array",
                    "items": {"type": "string"},
                }
            },
            "required": ["caps"],
            "additionalProperties": False,
        },
        hooks=("capable", "security_capable"),
    ),
)

PRIMITIVES_BY_ID: dict[str, Primitive] = {p.id: p for p in PRIMITIVES}
