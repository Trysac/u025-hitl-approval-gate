# Architecture

## Purpose

`trysac-hitl-approval-gate` is a small, dependency-free Python library that puts risky agent actions behind a payload-bound, expiring, single-use human approval with a hash-chained audit log.

## Shape

```text
caller code --> hitl_approval_gate (public API in __init__.py)
                    |
                    +-- ApprovalGate (state machine, threading.Lock)
                    +-- ApprovalStore: MemoryStore | JsonFileStore (atomic replace)
```

- **Public API**: the names listed in `__all__` of `src/hitl_approval_gate/__init__.py`. Anything else is internal.
- **Data**: `ApprovalRequest` and `AuditRecord` are frozen dataclasses. `AuditRecord.at` is an ISO 8601 UTC string.
- **Stores**: `JsonFileStore` re-reads the file on every operation and replaces it atomically through a fsynced temporary file. The built-in stores provide `commit(req, record)` so a request and its audit record are written together; other stores fall back to `save` plus `append_audit`.
- **Errors**: failures raise `ApprovalError` with a stable `code`; messages never contain payload values.
- **Logging**: a module logger with a `NullHandler`; the library never configures logging.

## Quality contract

`scripts/check.py` is the single definition of the gates; `fabrica.json` tells the factory and CI how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
