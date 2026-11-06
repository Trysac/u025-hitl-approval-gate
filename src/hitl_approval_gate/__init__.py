"""Human approval gate for agent actions with side effects.

An agent that wants to run a risky action calls ApprovalGate.request, a different human calls
ApprovalGate.approve or ApprovalGate.deny before a deadline, and only an approved, unexpired,
unused request whose payload still matches runs through ApprovalGate.execute. Every transition
is appended to a hash-chained audit log.

Threat model
------------
Defended:

* Replay: a request is consumed before the action runs, so a second execute is refused.
* Payload substitution: the canonical payload is hashed into the request and re-checked on
  execute.
* Expired approvals: approve, deny and execute are refused at or after ``expires_at``.
* Self-approval: the requester cannot approve their own request unless explicitly allowed.
* Audit edits or deletions: ``verify_audit`` reports the first record whose chain link is broken.

Not defended:

* Decider identity: ``by`` is a caller-supplied string; authenticate the human first.
* Whole-chain rewrites: an attacker who rewrites every record can forge a valid chain (dropping
  only the newest records also verifies); export the latest audit hash to a place the attacker
  cannot write and compare it.
* Multi-process races: a ``threading.Lock`` serializes calls in-process only.

Payload hashes use ``json.dumps`` with sorted keys. This is not RFC 8785 (JCS), so hashes are
only stable within Python.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import hashlib
import json
import logging
import math
import os
import secrets
import tempfile
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar, cast, get_args

__all__ = [
    "ApprovalError",
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalStore",
    "AuditRecord",
    "ErrorCode",
    "EventName",
    "JsonFileStore",
    "MemoryStore",
    "Status",
    "__version__",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar("T")

Status = Literal[
    "pending",
    "approved",
    "denied",
    "expired",
    "consumed",
]
EventName = Literal[
    "requested",
    "approved",
    "denied",
    "expired",
    "consumed",
    "execution_failed",
]
ErrorCode = Literal[
    "not_found",
    "already_decided",
    "expired",
    "not_approved",
    "already_consumed",
    "payload_mismatch",
    "self_approval",
    "payload_too_large",
    "store_corrupt",
    "store_full",
    "invalid_argument",
]

_STATUSES = get_args(Status)
_EVENTS = get_args(EventName)

MAX_TEXT_CHARS = 1000
MAX_ID_CHARS = 200
MAX_PAYLOAD_DEPTH = 32
GENESIS_HASH = "0" * 64
DEFAULT_TTL = timedelta(hours=1)
_SYSTEM_ACTOR = "system"


class ApprovalError(Exception):
    """Base error of the library; ``code`` is a stable machine-readable identifier."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        self.code: ErrorCode = code
        self.message = message[:200]
        super().__init__(self.message)


def _invalid(message: str) -> ApprovalError:
    return ApprovalError("invalid_argument", message)


@dataclasses.dataclass(frozen=True)
class ApprovalRequest:
    """An action awaiting, or having received, a human decision."""

    id: str
    action: str
    payload: dict[str, Any]
    payload_sha256: str
    requester: str
    reason: str
    created_at: datetime
    expires_at: datetime
    status: Status
    decided_by: str | None = None
    note: str | None = None


@dataclasses.dataclass(frozen=True)
class AuditRecord:
    """One link of the hash-chained audit log; ``at`` is an ISO 8601 UTC string."""

    seq: int
    at: str
    request_id: str
    event: EventName
    actor: str
    detail: str
    prev_hash: str
    hash: str


_Requests = list[ApprovalRequest]
_Records = list[AuditRecord]


class ApprovalStore(Protocol):
    """Storage behind an :class:`ApprovalGate`."""

    def save(self, req: ApprovalRequest) -> None:
        """Insert or replace a request by id."""

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Return the request with this id, or None."""

    def list(self, status: Status | None = None) -> _Requests:
        """Return requests in insertion order, optionally filtered by status."""

    def append_audit(self, record: AuditRecord) -> None:
        """Append a record to the audit log."""

    def audit(self) -> _Records:
        """Return the whole audit log in order."""


def _copy_request(req: ApprovalRequest) -> ApprovalRequest:
    return dataclasses.replace(req, payload=copy.deepcopy(req.payload))


class MemoryStore:
    """In-memory store; the gate bounds its size through ``max_requests``."""

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._records: list[AuditRecord] = []

    def save(self, req: ApprovalRequest) -> None:
        """Insert or replace a request by id."""
        self._requests[req.id] = _copy_request(req)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Return a copy of the request with this id, or None."""
        found = self._requests.get(request_id)
        return None if found is None else _copy_request(found)

    def list(self, status: Status | None = None) -> _Requests:
        """Return copies of the requests, optionally filtered by status."""
        found = [r for r in self._requests.values() if status is None or r.status == status]
        return [_copy_request(r) for r in found]

    def append_audit(self, record: AuditRecord) -> None:
        """Append a record to the audit log."""
        self._records.append(record)

    def audit(self) -> _Records:
        """Return a copy of the audit log."""
        return [*self._records]

    def commit(self, req: ApprovalRequest, record: AuditRecord) -> None:
        """Save a request and append its audit record together."""
        self.save(req)
        self.append_audit(record)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _str_field(data: Mapping[str, Any], key: str) -> str:
    value = data[key]
    if not isinstance(value, str):
        raise ValueError(key)
    return value


def _opt_str_field(data: Mapping[str, Any], key: str) -> str | None:
    value = data[key]
    if value is not None and not isinstance(value, str):
        raise ValueError(key)
    return value


def _dt_field(data: Mapping[str, Any], key: str) -> datetime:
    moment = datetime.fromisoformat(_str_field(data, key))
    if moment.utcoffset() is None:
        raise ValueError(key)
    return moment.astimezone(timezone.utc)


def _request_from_dict(data: object) -> ApprovalRequest:
    if not isinstance(data, dict) or set(data) != _REQUEST_KEYS:
        raise ValueError("bad request entry")
    status = _str_field(data, "status")
    payload = data["payload"]
    if status not in _STATUSES or not isinstance(payload, dict):
        raise ValueError("bad request entry")
    return ApprovalRequest(
        id=_str_field(data, "id"),
        action=_str_field(data, "action"),
        payload=payload,
        payload_sha256=_str_field(data, "payload_sha256"),
        requester=_str_field(data, "requester"),
        reason=_str_field(data, "reason"),
        created_at=_dt_field(data, "created_at"),
        expires_at=_dt_field(data, "expires_at"),
        status=cast(Status, status),
        decided_by=_opt_str_field(data, "decided_by"),
        note=_opt_str_field(data, "note"),
    )


def _record_from_dict(data: object) -> AuditRecord:
    if not isinstance(data, dict) or set(data) != _RECORD_KEYS:
        raise ValueError("bad audit entry")
    seq = data["seq"]
    event = _str_field(data, "event")
    if not isinstance(seq, int) or isinstance(seq, bool) or event not in _EVENTS:
        raise ValueError("bad audit entry")
    return AuditRecord(
        seq=seq,
        at=_str_field(data, "at"),
        request_id=_str_field(data, "request_id"),
        event=cast(EventName, event),
        actor=_str_field(data, "actor"),
        detail=_str_field(data, "detail"),
        prev_hash=_str_field(data, "prev_hash"),
        hash=_str_field(data, "hash"),
    )


def _request_to_dict(req: ApprovalRequest) -> dict[str, Any]:
    data = dataclasses.asdict(req)
    data["created_at"] = _iso(req.created_at)
    data["expires_at"] = _iso(req.expires_at)
    return data


def _upsert(requests: _Requests, req: ApprovalRequest) -> _Requests:
    merged = [req if item.id == req.id else item for item in requests]
    if all(item.id != req.id for item in requests):
        merged.append(req)
    return merged


_REQUEST_KEYS = frozenset(field.name for field in dataclasses.fields(ApprovalRequest))
_RECORD_KEYS = frozenset(field.name for field in dataclasses.fields(AuditRecord))


class JsonFileStore:
    """Store kept in one JSON file that is replaced atomically on every write.

    The file is re-read on every operation, so a fresh instance (or an edit by another
    process) is always seen. Writes go to a fsynced temporary file followed by ``os.replace``.
    A write that would make the file larger than ``max_bytes`` raises ``store_full``; a file
    that is larger than ``max_bytes`` or cannot be parsed raises ``store_corrupt``.
    """

    def __init__(self, path: Path, *, max_bytes: int = 50 * 2**20) -> None:
        if not isinstance(max_bytes, int) or max_bytes < 1:
            raise _invalid("max_bytes must be a positive integer")
        self._path = Path(path)
        self._max_bytes = max_bytes

    def _load(self) -> tuple[_Requests, _Records]:
        try:
            with self._path.open("rb") as handle:
                raw = handle.read(self._max_bytes + 1)
        except FileNotFoundError:
            return [], []
        except OSError:
            raise ApprovalError("store_corrupt", "cannot read the store file") from None
        if len(raw) > self._max_bytes:
            raise ApprovalError("store_corrupt", "store file exceeds max_bytes")
        try:
            doc = json.loads(raw.decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("version") != 1:
                raise ValueError("unsupported document")
            requests, records = doc["requests"], doc["audit"]
            if not isinstance(requests, list) or not isinstance(records, list):
                raise ValueError("bad collections")
            return (
                [_request_from_dict(item) for item in requests],
                [_record_from_dict(item) for item in records],
            )
        except (ValueError, KeyError, TypeError, RecursionError):
            raise ApprovalError("store_corrupt", "store file is corrupt") from None

    def _dump(self, requests: _Requests, records: _Records) -> None:
        doc = {
            "version": 1,
            "requests": [_request_to_dict(item) for item in requests],
            "audit": [dataclasses.asdict(item) for item in records],
        }
        data = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(data) > self._max_bytes:
            raise ApprovalError("store_full", "store file would exceed max_bytes")
        temp_name: str | None = None
        try:
            fd, temp_name = tempfile.mkstemp(
                dir=self._path.parent,
                prefix=f"{self._path.name}.",
                suffix=".tmp",
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self._path)
        except OSError:
            if temp_name is not None:
                with contextlib.suppress(OSError):
                    os.unlink(temp_name)
            raise ApprovalError("store_corrupt", "cannot write the store file") from None

    def save(self, req: ApprovalRequest) -> None:
        """Insert or replace a request by id."""
        requests, records = self._load()
        self._dump(_upsert(requests, req), records)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Return the request with this id, or None."""
        for item in self._load()[0]:
            if item.id == request_id:
                return item
        return None

    def list(self, status: Status | None = None) -> _Requests:
        """Return requests in insertion order, optionally filtered by status."""
        return [r for r in self._load()[0] if status is None or r.status == status]

    def append_audit(self, record: AuditRecord) -> None:
        """Append a record to the audit log."""
        requests, records = self._load()
        self._dump(requests, [*records, record])

    def audit(self) -> _Records:
        """Return the whole audit log in order."""
        return self._load()[1]

    def commit(self, req: ApprovalRequest, record: AuditRecord) -> None:
        """Save a request and append its audit record in one atomic file replacement."""
        requests, records = self._load()
        self._dump(_upsert(requests, req), [*records, record])


def _check_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT_CHARS:
        raise _invalid(f"{name} must be 1 to {MAX_TEXT_CHARS} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise _invalid(f"{name} is not valid Unicode text") from None
    return value


def _check_id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_ID_CHARS:
        raise _invalid(f"request id must be 1 to {MAX_ID_CHARS} characters")
    return value


def _check_ttl(ttl: object) -> timedelta:
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise _invalid("ttl must be a positive timedelta")
    return ttl


def _spend(budget: list[int], amount: int) -> None:
    budget[0] -= amount
    if budget[0] < 0:
        raise ApprovalError("payload_too_large", "payload exceeds the size limit")


def _plain(value: object, depth: int, budget: list[int]) -> Any:
    """Validate JSON-only data and return a plain copy; ``budget`` bounds the work done."""
    _spend(budget, 1)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _invalid("payload contains a non-finite number")
        return value
    if isinstance(value, str):
        _spend(budget, len(value))
        return value
    if isinstance(value, Mapping):
        if depth > MAX_PAYLOAD_DEPTH:
            raise _invalid("payload is nested too deeply")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise _invalid("payload keys must be strings")
            _spend(budget, len(key))
            out[key] = _plain(item, depth + 1, budget)
        return out
    if isinstance(value, list | tuple):
        if depth > MAX_PAYLOAD_DEPTH:
            raise _invalid("payload is nested too deeply")
        return [_plain(item, depth + 1, budget) for item in value]
    raise _invalid("payload contains a non-JSON value")


def _canonical_bytes(value: object) -> bytes:
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def _canonical_payload(payload: object, limit: int) -> bytes:
    if not isinstance(payload, Mapping):
        raise _invalid("payload must be a mapping")
    plain = _plain(payload, 1, [limit])
    try:
        data = _canonical_bytes(plain)
    except (TypeError, ValueError):
        raise _invalid("payload is not valid JSON data") from None
    if len(data) > limit:
        raise ApprovalError("payload_too_large", "payload exceeds the size limit")
    return data


def _record_body(record: AuditRecord) -> dict[str, Any]:
    body = dataclasses.asdict(record)
    del body["hash"]
    return body


def _body_hash(body: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _default_id_factory() -> str:
    return secrets.token_urlsafe(16)


class ApprovalGate:
    """Puts risky actions behind payload-bound, expiring, single-use human approval.

    A ``threading.Lock`` serializes calls in-process. ``on_event`` and the executed function
    run outside the lock, so they may call back into the gate.
    """

    def __init__(
        self,
        store: ApprovalStore,
        *,
        ttl: timedelta = DEFAULT_TTL,
        clock: Callable[[], datetime],
        id_factory: Callable[[], str] = _default_id_factory,
        allow_self_approval: bool = False,
        max_payload_bytes: int = 65_536,
        max_requests: int = 10_000,
        on_event: Callable[[Mapping[str, str]], None] | None = None,
    ) -> None:
        self._ttl = _check_ttl(ttl)
        if not isinstance(max_payload_bytes, int) or max_payload_bytes < 1:
            raise _invalid("max_payload_bytes must be a positive integer")
        if not isinstance(max_requests, int) or max_requests < 1:
            raise _invalid("max_requests must be a positive integer")
        self._store = store
        self._clock = clock
        self._id_factory = id_factory
        self._allow_self_approval = allow_self_approval
        self._max_payload_bytes = max_payload_bytes
        self._max_requests = max_requests
        self._on_event = on_event
        self._lock = threading.Lock()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise _invalid("clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _commit(self, req: ApprovalRequest, record: AuditRecord) -> None:
        commit = getattr(self._store, "commit", None)
        if callable(commit):
            commit(req, record)
        else:
            self._store.save(req)
            self._store.append_audit(record)

    def _next_record(
        self,
        request_id: str,
        event: EventName,
        actor: str,
        detail: str,
        at: datetime,
    ) -> AuditRecord:
        log = self._store.audit()
        record = AuditRecord(
            seq=len(log) + 1,
            at=_iso(at),
            request_id=request_id,
            event=event,
            actor=actor,
            detail=detail,
            prev_hash=log[-1].hash if log else GENESIS_HASH,
            hash="",
        )
        return dataclasses.replace(record, hash=_body_hash(_record_body(record)))

    def _transition(
        self,
        events: list[dict[str, str]],
        req: ApprovalRequest,
        event: EventName,
        actor: str,
        detail: str,
        at: datetime,
        *,
        only_audit: bool = False,
    ) -> None:
        record = self._next_record(req.id, event, actor, detail, at)
        if only_audit:
            self._store.append_audit(record)
        else:
            self._commit(req, record)
        events.append(
            {
                "event": event,
                "request_id": req.id,
                "actor": actor,
                "status": req.status,
            }
        )

    def _expire(self, events: list[dict[str, str]], req: ApprovalRequest, now: datetime) -> None:
        expired = dataclasses.replace(req, status="expired")
        self._transition(events, expired, "expired", _SYSTEM_ACTOR, "", now)

    def _emit(self, events: list[dict[str, str]]) -> None:
        if self._on_event is None:
            return
        for event in events:
            try:
                self._on_event(dict(event))
            except Exception as exc:
                logger.warning("on_event callback raised %s", type(exc).__name__)

    def request(
        self,
        action: str,
        payload: Mapping[str, Any],
        *,
        requester: str,
        reason: str,
        ttl: timedelta | None = None,
    ) -> ApprovalRequest:
        """Hash the payload into a new pending request and audit it.

        Raises:
            ApprovalError: ``invalid_argument``, ``payload_too_large`` or ``store_full``.
        """
        _check_text("action", action)
        _check_text("requester", requester)
        _check_text("reason", reason)
        lifetime = self._ttl if ttl is None else _check_ttl(ttl)
        data = _canonical_payload(payload, self._max_payload_bytes)
        stored: dict[str, Any] = json.loads(data)
        events: list[dict[str, str]] = []
        try:
            with self._lock:
                now = self._now()
                if len(self._store.list()) >= self._max_requests:
                    raise ApprovalError("store_full", "request limit reached")
                request_id = _check_id(self._id_factory())
                if self._store.get(request_id) is not None:
                    raise _invalid("id_factory returned an id that is already in use")
                try:
                    expires_at = now + lifetime
                except OverflowError:
                    raise _invalid("ttl is too large") from None
                created = ApprovalRequest(
                    id=request_id,
                    action=action,
                    payload=stored,
                    payload_sha256=hashlib.sha256(data).hexdigest(),
                    requester=requester,
                    reason=reason,
                    created_at=now,
                    expires_at=expires_at,
                    status="pending",
                )
                self._transition(events, created, "requested", requester, action, now)
                return created
        finally:
            self._emit(events)

    def _decide(
        self,
        request_id: str,
        by: str,
        note: str | None,
        outcome: Literal["approved", "denied"],
    ) -> ApprovalRequest:
        _check_id(request_id)
        _check_text("by", by)
        if note is not None:
            _check_text("note", note)
        events: list[dict[str, str]] = []
        try:
            with self._lock:
                req = self._store.get(request_id)
                if req is None:
                    raise ApprovalError("not_found", "no such request")
                if req.status == "expired":
                    raise ApprovalError("expired", "request has expired")
                if req.status != "pending":
                    raise ApprovalError("already_decided", "request was already decided")
                now = self._now()
                if now >= req.expires_at:
                    self._expire(events, req, now)
                    raise ApprovalError("expired", "request has expired")
                own = by == req.requester
                if outcome == "approved" and own and not self._allow_self_approval:
                    raise ApprovalError("self_approval", "self-approval refused")
                decided = dataclasses.replace(req, status=outcome, decided_by=by, note=note)
                self._transition(events, decided, outcome, by, note or "", now)
                return decided
        finally:
            self._emit(events)

    def approve(self, request_id: str, *, by: str, note: str | None = None) -> ApprovalRequest:
        """Approve a pending request.

        Raises:
            ApprovalError: ``not_found``, ``expired``, ``already_decided``, ``self_approval``
                or ``invalid_argument``.
        """
        return self._decide(request_id, by, note, "approved")

    def deny(self, request_id: str, *, by: str, note: str | None = None) -> ApprovalRequest:
        """Deny a pending request.

        Raises:
            ApprovalError: ``not_found``, ``expired``, ``already_decided`` or
                ``invalid_argument``.
        """
        return self._decide(request_id, by, note, "denied")

    def pending(self) -> list[ApprovalRequest]:
        """Expire stale requests, then return the requests still pending."""
        events: list[dict[str, str]] = []
        try:
            with self._lock:
                now = self._now()
                for req in self._store.list():
                    if req.status in ("pending", "approved") and now >= req.expires_at:
                        self._expire(events, req, now)
                return self._store.list("pending")
        finally:
            self._emit(events)

    def _claim(self, request_id: str, digest: str) -> ApprovalRequest:
        events: list[dict[str, str]] = []
        try:
            with self._lock:
                req = self._store.get(request_id)
                if req is None:
                    raise ApprovalError("not_found", "no such request")
                if req.status == "consumed":
                    raise ApprovalError("already_consumed", "request already consumed")
                now = self._now()
                if req.status == "expired":
                    raise ApprovalError("expired", "request has expired")
                if req.status == "approved" and now >= req.expires_at:
                    self._expire(events, req, now)
                    raise ApprovalError("expired", "request has expired")
                if req.status != "approved":
                    raise ApprovalError("not_approved", "request is not approved")
                if req.payload_sha256 != digest:
                    raise ApprovalError("payload_mismatch", "payload does not match")
                consumed = dataclasses.replace(req, status="consumed")
                self._transition(events, consumed, "consumed", req.requester, "", now)
                return consumed
        finally:
            self._emit(events)

    def _record_failure(self, req: ApprovalRequest, exc: BaseException) -> None:
        events: list[dict[str, str]] = []
        try:
            with self._lock:
                detail = type(exc).__name__[:MAX_TEXT_CHARS]
                self._transition(
                    events,
                    req,
                    "execution_failed",
                    req.requester,
                    detail,
                    self._now(),
                    only_audit=True,
                )
        finally:
            self._emit(events)

    def execute(
        self,
        request_id: str,
        payload: Mapping[str, Any],
        fn: Callable[[Mapping[str, Any]], T],
    ) -> T:
        """Run ``fn(payload)`` once if the request is approved, unexpired and matches.

        The request is recorded as consumed before ``fn`` runs and outside the lock. If ``fn``
        raises, an ``execution_failed`` record with the exception type name is appended and the
        exception is re-raised.

        Raises:
            ApprovalError: ``not_found``, ``already_consumed``, ``expired``, ``not_approved``,
                ``payload_mismatch``, ``payload_too_large`` or ``invalid_argument``.
        """
        _check_id(request_id)
        data = _canonical_payload(payload, self._max_payload_bytes)
        consumed = self._claim(request_id, hashlib.sha256(data).hexdigest())
        try:
            return fn(json.loads(data))
        except BaseException as exc:
            self._record_failure(consumed, exc)
            raise

    def verify_audit(self) -> tuple[bool, int | None]:
        """Recompute the hash chain.

        Returns ``(True, None)`` when intact, else ``(False, position)`` with the 1-based
        position of the first bad record (deleted records show up as sequence gaps).
        """
        with self._lock:
            records = self._store.audit()
        expected_prev = GENESIS_HASH
        for position, record in enumerate(records, start=1):
            linked = record.seq == position and record.prev_hash == expected_prev
            if not linked or record.hash != _body_hash(_record_body(record)):
                return False, position
            expected_prev = record.hash
        return True, None
