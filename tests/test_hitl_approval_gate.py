"""Tests for hitl_approval_gate, exercising the public API only."""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import hitl_approval_gate
from hitl_approval_gate import ApprovalError, ApprovalGate, JsonFileStore, MemoryStore

T0 = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
PAYLOAD = {"to": "acct-7", "amount": 10, "memo": "h\u00e9llo"}
SENTINEL = "SENTINEL-4f1c9b"
NOTHING = object()


class FakeClock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def make_gate(
    store: Any = None,
    clock: FakeClock | None = None,
    **kwargs: Any,
) -> tuple[ApprovalGate, FakeClock, Any]:
    clock = clock if clock is not None else FakeClock()
    store = store if store is not None else MemoryStore()
    counter = itertools.count(1)
    kwargs.setdefault("id_factory", lambda: f"req-{next(counter)}")
    return ApprovalGate(store, clock=clock, **kwargs), clock, store


def request(gate: ApprovalGate, payload: Any = NOTHING) -> Any:
    body = PAYLOAD if payload is NOTHING else payload
    return gate.request("wire", body, requester="alice", reason="invoice 42")


def canonical(payload: object) -> bytes:
    text = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def code_of(call: Callable[[], object]) -> str:
    with pytest.raises(ApprovalError) as info:
        call()
    return str(info.value.code)


def status_of(store: Any, request_id: str) -> str:
    found = store.get(request_id)
    assert found is not None
    return str(found.status)


def events_of(store: Any) -> list[str]:
    return [record.event for record in store.audit()]


def in_state(gate: ApprovalGate, state: str) -> str:
    req = request(gate)
    if state in ("approved", "consumed"):
        gate.approve(req.id, by="bob")
    if state == "denied":
        gate.deny(req.id, by="bob")
    if state == "consumed":
        gate.execute(req.id, PAYLOAD, lambda payload: None)
    return str(req.id)


def edit_file(path: Path, change: Callable[[dict[str, Any]], object]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def fresh_gate(path: Path) -> ApprovalGate:
    return ApprovalGate(JsonFileStore(path), clock=FakeClock())


def consumed_file(tmp_path: Path) -> Path:
    path = tmp_path / "store.json"
    gate, _, _ = make_gate(store=JsonFileStore(path))
    in_state(gate, "consumed")
    assert gate.verify_audit() == (True, None)
    return path


SPEC_FRAGMENT = (
    "), ensure_ascii=False, allow_nan=False) in UTF-8, and appends an audit record with event "
)


def test_request_spec_fragment_utf8_hash_and_event() -> None:
    assert SPEC_FRAGMENT.endswith("with event ")
    gate, _, store = make_gate()
    req = request(gate)
    expected = json.dumps(
        PAYLOAD, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    assert req.payload_sha256 == hashlib.sha256(expected).hexdigest()
    assert store.audit()[0].event == "requested"


def test_request_is_pending_hashed_and_audited() -> None:
    gate, clock, store = make_gate(ttl=timedelta(hours=1))
    req = request(gate)
    assert req.status == "pending"
    assert req.expires_at == clock.now + timedelta(hours=1)
    assert req.created_at == T0
    assert req.payload_sha256 == hashlib.sha256(canonical(PAYLOAD)).hexdigest()
    assert req.payload == PAYLOAD
    assert req.decided_by is None
    assert req.note is None
    assert store.get(req.id) == req
    log = store.audit()
    assert [record.event for record in log] == ["requested"]
    assert log[0].seq == 1
    assert log[0].prev_hash == "0" * 64
    assert log[0].request_id == req.id
    assert log[0].at == "2025-01-01T12:00:00+00:00"


def test_hash_ignores_key_order_and_execute_accepts_reordered_payload() -> None:
    gate, _, _ = make_gate()
    first = request(gate, {"a": 1, "b": [1, 2]})
    second = request(gate, {"b": [1, 2], "a": 1})
    assert first.payload_sha256 == second.payload_sha256
    gate.approve(first.id, by="bob")
    assert gate.execute(first.id, {"b": [1, 2], "a": 1}, lambda payload: payload["a"]) == 1


def test_ttl_override_and_invalid_ttl() -> None:
    gate, clock, _ = make_gate()
    short = gate.request("w", {}, requester="a", reason="r", ttl=timedelta(minutes=5))
    assert short.expires_at == clock.now + timedelta(minutes=5)
    for bad in (timedelta(0), timedelta(minutes=-1), 5, timedelta.max):
        code = code_of(lambda bad=bad: gate.request("w", {}, requester="a", reason="r", ttl=bad))
        assert code == "invalid_argument"


@pytest.mark.parametrize(
    ("op", "state"),
    [
        ("approve", "approved"),
        ("approve", "denied"),
        ("approve", "consumed"),
        ("deny", "approved"),
        ("deny", "denied"),
        ("deny", "consumed"),
    ],
)
def test_decided_requests_cannot_be_decided_again(op: str, state: str) -> None:
    gate, _, store = make_gate()
    rid = in_state(gate, state)
    before = store.get(rid)
    count = len(store.audit())
    assert code_of(lambda: getattr(gate, op)(rid, by="carol")) == "already_decided"
    assert store.get(rid) == before
    assert len(store.audit()) == count


@pytest.mark.parametrize("op", ["approve", "deny"])
def test_decision_at_expires_at_expires_the_request(op: str) -> None:
    gate, clock, store = make_gate()
    req = request(gate)
    clock.now = req.expires_at
    assert code_of(lambda: getattr(gate, op)(req.id, by="bob")) == "expired"
    assert status_of(store, req.id) == "expired"
    assert events_of(store) == ["requested", "expired"]
    count = len(store.audit())
    assert code_of(lambda: gate.approve(req.id, by="bob")) == "expired"
    assert code_of(lambda: gate.deny(req.id, by="bob")) == "expired"
    assert code_of(lambda: gate.execute(req.id, PAYLOAD, lambda payload: None)) == "expired"
    assert len(store.audit()) == count


def test_defends_expired_approval_execute_at_expires_at() -> None:
    gate, clock, store = make_gate()
    rid = in_state(gate, "approved")
    clock.now = store.get(rid).expires_at
    called: list[object] = []
    assert code_of(lambda: gate.execute(rid, PAYLOAD, called.append)) == "expired"
    assert called == []
    assert status_of(store, rid) == "expired"
    assert events_of(store) == ["requested", "approved", "expired"]
    assert code_of(lambda: gate.execute(rid, PAYLOAD, called.append)) == "expired"
    assert len(store.audit()) == 3


def test_execute_of_stale_pending_request_is_not_approved() -> None:
    gate, clock, store = make_gate()
    req = request(gate)
    clock.now = req.expires_at
    assert code_of(lambda: gate.execute(req.id, PAYLOAD, lambda payload: None)) == "not_approved"
    assert status_of(store, req.id) == "pending"


def test_pending_expires_stale_requests_first() -> None:
    gate, clock, store = make_gate()
    stale = request(gate)
    approved_stale = request(gate)
    gate.approve(approved_stale.id, by="bob")
    clock.advance(timedelta(minutes=30))
    young = request(gate)
    assert [r.id for r in gate.pending()] == [stale.id, young.id]
    clock.advance(timedelta(minutes=31))
    assert [r.id for r in gate.pending()] == [young.id]
    assert status_of(store, stale.id) == "expired"
    assert status_of(store, approved_stale.id) == "expired"
    assert events_of(store).count("expired") == 2
    assert gate.pending() == [store.get(young.id)]
    assert events_of(store).count("expired") == 2


def test_defends_payload_substitution() -> None:
    gate, _, store = make_gate()
    rid = in_state(gate, "approved")
    calls: list[object] = []
    tampered = dict(PAYLOAD, amount=10_000)
    assert code_of(lambda: gate.execute(rid, tampered, calls.append)) == "payload_mismatch"
    assert calls == []
    assert status_of(store, rid) == "approved"
    assert events_of(store) == ["requested", "approved"]


def test_defends_replay_and_fn_runs_once() -> None:
    gate, _, store = make_gate()
    rid = in_state(gate, "approved")
    calls: list[object] = []
    assert gate.execute(rid, PAYLOAD, lambda payload: calls.append(payload) or 42) == 42
    assert calls == [PAYLOAD]
    assert code_of(lambda: gate.execute(rid, PAYLOAD, calls.append)) == "already_consumed"
    assert len(calls) == 1
    assert status_of(store, rid) == "consumed"
    assert events_of(store) == ["requested", "approved", "consumed"]


def test_failing_fn_is_audited_and_reraised() -> None:
    gate, _, store = make_gate()
    rid = in_state(gate, "approved")
    calls: list[object] = []

    def boom(payload: Any) -> None:
        calls.append(payload)
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        gate.execute(rid, PAYLOAD, boom)
    assert status_of(store, rid) == "consumed"
    last = store.audit()[-1]
    assert last.event == "execution_failed"
    assert last.detail == "RuntimeError"
    assert code_of(lambda: gate.execute(rid, PAYLOAD, boom)) == "already_consumed"
    assert len(calls) == 1
    assert gate.verify_audit() == (True, None)


def test_base_exception_from_fn_is_audited_and_reraised() -> None:
    gate, _, store = make_gate()
    rid = in_state(gate, "approved")

    def interrupted(payload: Any) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        gate.execute(rid, PAYLOAD, interrupted)
    assert store.audit()[-1].detail == "KeyboardInterrupt"


def test_execute_requires_an_approved_request() -> None:
    gate, _, _ = make_gate()
    pending_id = request(gate).id
    denied_id = in_state(gate, "denied")
    for rid in (pending_id, denied_id):
        code = code_of(lambda rid=rid: gate.execute(rid, PAYLOAD, lambda payload: None))
        assert code == "not_approved"
    assert code_of(lambda: gate.execute("nope", PAYLOAD, lambda payload: None)) == "not_found"


def test_unknown_ids_are_not_found_and_bad_ids_invalid() -> None:
    gate, _, store = make_gate()
    assert code_of(lambda: gate.approve("nope", by="bob")) == "not_found"
    assert code_of(lambda: gate.deny("nope", by="bob")) == "not_found"
    assert store.audit() == []
    assert code_of(lambda: gate.approve(5, by="bob")) == "invalid_argument"  # type: ignore
    assert code_of(lambda: gate.execute("", PAYLOAD, lambda payload: None)) == "invalid_argument"


def test_defends_self_approval() -> None:
    gate, _, store = make_gate()
    req = request(gate)
    assert code_of(lambda: gate.approve(req.id, by="alice")) == "self_approval"
    assert status_of(store, req.id) == "pending"
    assert events_of(store) == ["requested"]
    denied = gate.deny(req.id, by="alice")
    assert denied.status == "denied"
    assert denied.decided_by == "alice"


def test_self_approval_can_be_allowed() -> None:
    gate, _, _ = make_gate(allow_self_approval=True)
    req = request(gate)
    assert gate.approve(req.id, by="alice", note="fine").note == "fine"


def test_verify_audit_on_untouched_and_empty_log() -> None:
    gate, _, _ = make_gate()
    assert gate.verify_audit() == (True, None)
    in_state(gate, "consumed")
    assert gate.verify_audit() == (True, None)


def test_defends_audit_edit(tmp_path: Path) -> None:
    path = consumed_file(tmp_path)
    edit_file(path, lambda data: data["audit"][1].update(actor="mallory"))
    assert fresh_gate(path).verify_audit() == (False, 2)


def test_defends_audit_deletion(tmp_path: Path) -> None:
    path = consumed_file(tmp_path)
    edit_file(path, lambda data: data["audit"].pop(1))
    assert fresh_gate(path).verify_audit() == (False, 2)


@pytest.mark.parametrize(
    ("index", "field", "value", "position"),
    [
        (0, "detail", "other", 1),
        (0, "request_id", "req-9", 1),
        (1, "hash", "f" * 64, 2),
        (1, "seq", 9, 2),
        (2, "prev_hash", "0" * 64, 3),
        (2, "at", "2030-01-01T00:00:00+00:00", 3),
    ],
)
def test_other_audit_edits_are_located(
    tmp_path: Path,
    index: int,
    field: str,
    value: object,
    position: int,
) -> None:
    path = consumed_file(tmp_path)
    edit_file(path, lambda data: data["audit"][index].update({field: value}))
    assert fresh_gate(path).verify_audit() == (False, position)


def test_reloaded_store_continues_with_same_requests_and_audit(tmp_path: Path) -> None:
    path = tmp_path / "store.json"
    gate1, clock, _ = make_gate(store=JsonFileStore(path))
    req = request(gate1)
    ids = iter(["other-1"])
    gate2 = ApprovalGate(JsonFileStore(path), clock=clock, id_factory=lambda: next(ids))
    assert gate2.pending() == [req]
    gate2.approve(req.id, by="bob")
    second = request(gate2)
    reloaded = JsonFileStore(path)
    assert [record.seq for record in reloaded.audit()] == [1, 2, 3]
    assert [r.id for r in reloaded.list()] == [req.id, second.id]
    assert status_of(reloaded, req.id) == "approved"
    assert [r.id for r in reloaded.list("pending")] == [second.id]
    assert reloaded.get("missing") is None
    assert gate2.verify_audit() == (True, None)


def test_missing_file_is_an_empty_store(tmp_path: Path) -> None:
    store = JsonFileStore(tmp_path / "missing.json")
    assert store.list() == []
    assert store.audit() == []
    assert store.get("x") is None


def test_truncated_file_is_corrupt(tmp_path: Path) -> None:
    path = consumed_file(tmp_path)
    raw = path.read_bytes()
    half = len(raw) // 2
    path.write_bytes(raw[:half])
    assert code_of(lambda: JsonFileStore(path).audit()) == "store_corrupt"
    assert code_of(lambda: fresh_gate(path).pending()) == "store_corrupt"
    assert code_of(lambda: fresh_gate(path).verify_audit()) == "store_corrupt"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"\xff\xfe",
        b"[" * 100_000,
        b'{"version": 2, "requests": [], "audit": []}',
        b'{"version": 1, "requests": {}, "audit": []}',
        b'{"version": 1, "requests": [1], "audit": []}',
        b'{"version": 1, "requests": [], "audit": [1]}',
        b'{"version": 1, "requests": []}',
    ],
)
def test_malformed_documents_are_corrupt(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "store.json"
    path.write_bytes(raw)
    assert code_of(lambda: JsonFileStore(path).list()) == "store_corrupt"


MUTATIONS = [
    lambda d: d["requests"][0].update(status="bogus"),
    lambda d: d["requests"][0].update(payload=[]),
    lambda d: d["requests"][0].update(created_at="2025-01-01T12:00:00"),
    lambda d: d["requests"][0].update(created_at="nope"),
    lambda d: d["requests"][0].update(note=5),
    lambda d: d["requests"][0].update(id=5),
    lambda d: d["requests"][0].pop("note"),
    lambda d: d["audit"][0].update(seq=True),
    lambda d: d["audit"][0].update(event="bogus"),
    lambda d: d["audit"][0].update(extra="x"),
]


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_structurally_invalid_entries_are_corrupt(
    tmp_path: Path,
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    path = consumed_file(tmp_path)
    edit_file(path, mutation)
    assert code_of(lambda: JsonFileStore(path).list()) == "store_corrupt"


def test_oversized_file_is_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "store.json"
    path.write_bytes(b"x" * 500)
    assert code_of(lambda: JsonFileStore(path, max_bytes=100).audit()) == "store_corrupt"


def test_unwritable_location_is_reported(tmp_path: Path) -> None:
    gate, _, _ = make_gate(store=JsonFileStore(tmp_path / "missing-dir" / "store.json"))
    assert code_of(lambda: request(gate)) == "store_corrupt"


def test_json_store_rejects_bad_max_bytes(tmp_path: Path) -> None:
    assert code_of(lambda: JsonFileStore(tmp_path / "s.json", max_bytes=0)) == "invalid_argument"


def test_payload_size_limit() -> None:
    gate, _, _ = make_gate()
    assert code_of(lambda: request(gate, {"data": "x" * 65_536})) == "payload_too_large"
    overhead = len(canonical({"data": ""}))
    edge = {"data": "x" * (65_536 - overhead)}
    assert len(canonical(edge)) == 65_536
    assert request(gate, edge).status == "pending"
    assert code_of(lambda: request(gate, {"k": list(range(70_000))})) == "payload_too_large"
    assert code_of(lambda: request(gate, {"k" * 70_000: 1})) == "payload_too_large"
    big = {"data": "x" * 65_536}
    assert code_of(lambda: gate.execute("req-1", big, lambda payload: None)) == "payload_too_large"


def test_custom_payload_limit() -> None:
    gate, _, _ = make_gate(max_payload_bytes=10)
    assert code_of(lambda: request(gate, {"data": "x" * 20})) == "payload_too_large"


def nested(levels: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(levels):
        value = {"a": value}
    return value


CYCLE: dict[str, Any] = {}
CYCLE["self"] = CYCLE

BAD_PAYLOADS = [
    {"x": float("nan")},
    {"x": float("inf")},
    {"x": object()},
    {"x": {1, 2}},
    {"x": b"bytes"},
    {"x": "\ud800"},
    {1: "a"},
    ["a"],
    "text",
    None,
    CYCLE,
    nested(32),
]


@pytest.mark.parametrize("bad", BAD_PAYLOADS, ids=range(len(BAD_PAYLOADS)))
def test_non_json_payloads_are_invalid(bad: object) -> None:
    gate, _, store = make_gate()
    assert code_of(lambda: request(gate, bad)) == "invalid_argument"
    assert store.list() == []
    assert code_of(lambda: gate.execute("req-1", bad, lambda payload: None)) == "invalid_argument"


def test_json_types_are_accepted_and_normalized() -> None:
    gate, _, _ = make_gate()
    body = {"t": (1, 2.5, True, None, "s"), "n": {"k": [1]}}
    assert request(gate, body).payload == {"t": [1, 2.5, True, None, "s"], "n": {"k": [1]}}
    assert request(gate, nested(31)).status == "pending"
    assert request(gate, {}).payload == {}


@pytest.mark.parametrize("kind", ["memory", "file"])
def test_request_beyond_max_requests_is_store_full(tmp_path: Path, kind: str) -> None:
    backing = MemoryStore() if kind == "memory" else JsonFileStore(tmp_path / "s.json")
    gate, _, store = make_gate(store=backing, max_requests=2)
    first = request(gate)
    request(gate)
    assert code_of(lambda: request(gate)) == "store_full"
    assert len(store.list()) == 2
    assert len(store.audit()) == 2
    assert gate.approve(first.id, by="bob").status == "approved"


def test_json_store_refuses_to_pass_max_bytes(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    gate, _, store = make_gate(store=JsonFileStore(path, max_bytes=1500))
    created = 0
    with pytest.raises(ApprovalError) as info:
        for _ in range(20):
            request(gate)
            created += 1
    assert info.value.code == "store_full"
    assert 1 <= created < 20
    assert len(store.list()) == created
    assert len(store.audit()) == created
    assert path.stat().st_size <= 1500
    assert gate.verify_audit() == (True, None)


def test_on_event_payloads_never_contain_payload_values() -> None:
    events: list[Any] = []
    gate, clock, store = make_gate(on_event=events.append)
    body = {"memo": SENTINEL}
    req = request(gate, body)
    gate.approve(req.id, by="bob", note="ok")

    def fail(payload: Any) -> None:
        raise ValueError("bad")

    with pytest.raises(ValueError):
        gate.execute(req.id, body, fail)
    second = request(gate, body)
    gate.approve(second.id, by="bob")
    with pytest.raises(ApprovalError) as info:
        gate.execute(second.id, {"memo": SENTINEL + "x"}, fail)
    assert info.value.code == "payload_mismatch"
    assert SENTINEL not in str(info.value)
    third = request(gate, body)
    clock.advance(timedelta(hours=2))
    assert gate.pending() == []
    assert all(set(event) == {"event", "request_id", "actor", "status"} for event in events)
    assert [(e["event"], e["status"]) for e in events[:4]] == [
        ("requested", "pending"),
        ("approved", "approved"),
        ("consumed", "consumed"),
        ("execution_failed", "consumed"),
    ]
    assert {"event": "expired", "request_id": third.id, "actor": "system", "status": "expired"} in (
        events
    )
    assert SENTINEL not in repr(events)
    assert SENTINEL not in repr(store.audit())


def test_failing_on_event_callback_does_not_break_the_gate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken(event: Any) -> None:
        raise RuntimeError("callback failed")

    gate, _, _ = make_gate(on_event=broken)
    with caplog.at_level(logging.WARNING, logger="hitl_approval_gate"):
        req = request(gate)
    assert req.status == "pending"
    assert "RuntimeError" in caplog.text


def test_library_installs_only_a_null_handler() -> None:
    handlers = logging.getLogger("hitl_approval_gate").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


@pytest.mark.parametrize("bad", ["", "x" * 1001, 5, None, "\ud800"])
def test_text_arguments_are_validated(bad: Any) -> None:
    gate, _, _ = make_gate()
    req = request(gate)
    assert code_of(lambda: gate.request(bad, {}, requester="a", reason="r")) == "invalid_argument"
    assert code_of(lambda: gate.request("w", {}, requester=bad, reason="r")) == "invalid_argument"
    assert code_of(lambda: gate.request("w", {}, requester="a", reason=bad)) == "invalid_argument"
    assert code_of(lambda: gate.approve(req.id, by=bad)) == "invalid_argument"
    if bad is not None:
        assert code_of(lambda: gate.deny(req.id, by="bob", note=bad)) == "invalid_argument"
    assert gate.approve(req.id, by="x" * 1000, note="y" * 1000).status == "approved"


def test_constructor_arguments_are_validated() -> None:
    clock = FakeClock()
    assert code_of(lambda: ApprovalGate(MemoryStore(), clock=clock, ttl=timedelta(0))) == (
        "invalid_argument"
    )
    assert code_of(lambda: ApprovalGate(MemoryStore(), clock=clock, max_payload_bytes=0)) == (
        "invalid_argument"
    )
    assert code_of(lambda: ApprovalGate(MemoryStore(), clock=clock, max_requests=0)) == (
        "invalid_argument"
    )


def test_clock_must_be_timezone_aware() -> None:
    naive = ApprovalGate(MemoryStore(), clock=lambda: datetime(2025, 1, 1))
    assert code_of(lambda: request(naive)) == "invalid_argument"
    wrong = ApprovalGate(MemoryStore(), clock=lambda: "now")  # type: ignore
    assert code_of(lambda: request(wrong)) == "invalid_argument"


def test_id_factory_results_are_validated() -> None:
    empty, _, _ = make_gate(id_factory=lambda: "")
    assert code_of(lambda: request(empty)) == "invalid_argument"
    duplicate, _, _ = make_gate(id_factory=lambda: "same")
    request(duplicate)
    assert code_of(lambda: request(duplicate)) == "invalid_argument"


def test_default_id_factory_gives_unique_ids() -> None:
    gate = ApprovalGate(MemoryStore(), clock=FakeClock())
    first = request(gate)
    second = request(gate)
    assert first.id != second.id
    assert len(first.id) >= 16


def test_approval_error_has_stable_code_and_bounded_message() -> None:
    error = ApprovalError("not_found", "x" * 500)
    assert error.code == "not_found"
    assert len(str(error)) == 200
    assert len(error.message) == 200


def test_memory_store_isolates_stored_requests() -> None:
    gate, _, store = make_gate()
    req = request(gate)
    fetched = store.get(req.id)
    fetched.payload["to"] = "evil"
    assert store.get(req.id).payload["to"] == "acct-7"
    store.list()[0].payload["to"] = "evil"
    assert store.get(req.id) == req
    assert [r.id for r in store.list("pending")] == [req.id]
    assert store.list("approved") == []
    store.audit().clear()
    assert len(store.audit()) == 1


class PlainStore:
    """A store that implements only the five protocol methods."""

    def __init__(self) -> None:
        self.inner = MemoryStore()

    def save(self, req: Any) -> None:
        self.inner.save(req)

    def get(self, request_id: str) -> Any:
        return self.inner.get(request_id)

    def list(self, status: Any = None) -> Any:
        return self.inner.list(status)

    def append_audit(self, record: Any) -> None:
        self.inner.append_audit(record)

    def audit(self) -> Any:
        return self.inner.audit()


def test_gate_works_with_a_store_that_has_no_commit_method() -> None:
    gate, _, store = make_gate(store=PlainStore())
    in_state(gate, "consumed")
    assert events_of(store) == ["requested", "approved", "consumed"]
    assert gate.verify_audit() == (True, None)


def test_concurrent_execute_runs_fn_once() -> None:
    gate, _, _ = make_gate()
    rid = in_state(gate, "approved")
    calls: list[int] = []
    outcomes: list[str] = []

    def worker() -> None:
        try:
            gate.execute(rid, PAYLOAD, lambda payload: calls.append(1))
            outcomes.append("ok")
        except ApprovalError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(calls) == 1
    assert sorted(outcomes) == ["already_consumed"] * 7 + ["ok"]


def test_on_event_may_call_back_into_the_gate() -> None:
    seen: list[int] = []
    holder: list[ApprovalGate] = []

    def on_event(event: Any) -> None:
        seen.append(len(holder[0].pending()))

    gate, _, _ = make_gate(on_event=on_event)
    holder.append(gate)
    request(gate)
    assert seen == [1]


def test_module_documents_threat_model_and_version() -> None:
    assert "Threat model" in (hitl_approval_gate.__doc__ or "")
    assert hitl_approval_gate.__version__ == "0.1.0"
