"""WebSocket protocol message types shared between daemon and agents."""

from __future__ import annotations

import json
from typing import Literal

import msgspec


class EventData(msgspec.Struct):
    """Payload of an eBPF event from the daemon."""
    type: str
    resource: str
    data: dict
    timestamp: str


class Subscribe(msgspec.Struct):
    """Agent → Daemon: register and subscribe to event types."""
    type: str = "subscribe"
    agent_id: str = ""
    events: list[str] = []


class Event(msgspec.Struct):
    """Daemon → Agent: new event, creates a session."""
    type: str = "event"
    session: str = ""
    event: EventData | None = None


class ToolCall(msgspec.Struct):
    """Agent → Daemon: call a tool within a session."""
    type: str = "tool_call"
    session: str = ""
    call_id: str = ""
    name: str = ""
    args: dict = {}


class ToolResult(msgspec.Struct):
    """Daemon → Agent: result of a tool call."""
    type: str = "tool_result"
    session: str = ""
    call_id: str = ""
    result: dict = {}


class SessionDone(msgspec.Struct):
    """Agent → Daemon: agent is done with this session."""
    type: str = "session_done"
    session: str = ""


_subscribe_dec = msgspec.json.Decoder(Subscribe)
_tool_call_dec = msgspec.json.Decoder(ToolCall)
_session_done_dec = msgspec.json.Decoder(SessionDone)

_incoming_decoders: dict[str, msgspec.json.Decoder] = {
    "subscribe": _subscribe_dec,
    "tool_call": _tool_call_dec,
    "session_done": _session_done_dec,
}

# Union type for decoding any incoming message
IncomingMessage = Subscribe | ToolCall | SessionDone


class _IncomingDecoder:
    """Dispatches incoming JSON to the correct Struct decoder by 'type' field."""

    def decode(self, data: bytes) -> Subscribe | ToolCall | SessionDone:
        raw = json.loads(data)
        msg_type = raw.get("type", "")
        decoder = _incoming_decoders.get(msg_type)
        if decoder is None:
            raise msgspec.DecodeError(f"Unknown incoming message type: {msg_type!r}")
        return decoder.decode(data)


# Decoder that routes by "type" field
incoming_decoder = _IncomingDecoder()

# Typed decoders for specific message types
event_decoder = msgspec.json.Decoder(Event)
tool_result_decoder = msgspec.json.Decoder(ToolResult)
