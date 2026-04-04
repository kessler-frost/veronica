"""tests/test_protocol.py"""
import msgspec
from veronica.protocol.messages import (
    EventData, Subscribe, Event, ToolCall, ToolResult, SessionDone, incoming_decoder,
)

def test_subscribe_roundtrip():
    msg = Subscribe(agent_id="net-01", events=["net_connect", "process_exec"])
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=Subscribe)
    assert decoded.agent_id == "net-01"
    assert decoded.events == ["net_connect", "process_exec"]
    assert decoded.type == "subscribe"

def test_event_roundtrip():
    event = Event(
        session="abc123",
        event=EventData(type="net_connect", resource="ip:10.0.0.5:443",
                       data={"comm": "curl", "pid": 1234}, timestamp="2026-04-04T12:00:00Z"),
    )
    data = msgspec.json.encode(event)
    decoded = msgspec.json.decode(data, type=Event)
    assert decoded.session == "abc123"
    assert decoded.event.type == "net_connect"
    assert decoded.event.data["comm"] == "curl"

def test_tool_call_roundtrip():
    msg = ToolCall(session="abc123", call_id="1", name="map_read", args={"map": "connections"})
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=ToolCall)
    assert decoded.name == "map_read"
    assert decoded.args["map"] == "connections"

def test_tool_result_roundtrip():
    msg = ToolResult(session="abc123", call_id="1", result={"ok": True, "data": {"key": "value"}})
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=ToolResult)
    assert decoded.result["ok"] is True

def test_session_done_roundtrip():
    msg = SessionDone(session="abc123")
    data = msgspec.json.encode(msg)
    decoded = msgspec.json.decode(data, type=SessionDone)
    assert decoded.session == "abc123"

def test_incoming_decoder_routes_subscribe():
    data = msgspec.json.encode(Subscribe(agent_id="a", events=["x"]))
    msg = incoming_decoder.decode(data)
    assert isinstance(msg, Subscribe)

def test_incoming_decoder_routes_tool_call():
    data = msgspec.json.encode(ToolCall(session="s", call_id="1", name="read_file", args={"path": "/tmp"}))
    msg = incoming_decoder.decode(data)
    assert isinstance(msg, ToolCall)

def test_incoming_decoder_routes_session_done():
    data = msgspec.json.encode(SessionDone(session="s"))
    msg = incoming_decoder.decode(data)
    assert isinstance(msg, SessionDone)
