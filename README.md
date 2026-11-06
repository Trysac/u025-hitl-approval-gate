# hitl-approval-gate

[![PyPI version](https://img.shields.io/pypi/v/trysac-hitl-approval-gate)](https://pypi.org/project/trysac-hitl-approval-gate/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-hitl-approval-gate)](LICENSE)
[![CI](https://github.com/Trysac/u025-hitl-approval-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u025-hitl-approval-gate/actions/workflows/ci.yml)

Human approval gate for agent actions with side effects: payload-bound requests, expiry, single use, no self-approval and a hash-chained audit log.

## Problem

Agents that send emails, move money or change infrastructure need a human to approve some actions. Ad hoc confirmation prompts have no expiry and no audit trail, and an approval can be replayed or the payload swapped after approval. This library hashes the exact payload into a request, requires a different human to decide before a deadline, and runs the action only when the request is approved, unexpired, unused and the payload matches.

Unlike HumanLayer, which is a hosted service, this is a zero-dependency library that runs in your process.

## Install

```sh
pip install trysac-hitl-approval-gate
# or
uv add trysac-hitl-approval-gate
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from datetime import datetime, timezone

from hitl_approval_gate import ApprovalError, ApprovalGate, MemoryStore

gate = ApprovalGate(MemoryStore(), clock=lambda: datetime.now(timezone.utc))

payload = {"to": "cfo@example.com", "amount": 1200}
req = gate.request("send_payment", payload, requester="alice", reason="Invoice 42")

gate.approve(req.id, by="bob")  # a different human decides

result = gate.execute(req.id, payload, lambda p: f"paid {p['amount']}")
print(result)  # -> "paid 1200"

try:
    gate.execute(req.id, payload, lambda p: None)  # single use
except ApprovalError as exc:
    print(exc.code)  # -> "already_consumed"

print(gate.verify_audit())  # -> (True, None)
```

## Public API

- `ApprovalGate(store, *, ttl=timedelta(hours=1), clock, id_factory, allow_self_approval=False, max_payload_bytes=65_536, max_requests=10_000, on_event=None)`
- `request(action, payload, *, requester, reason, ttl=None) -> ApprovalRequest`: creates a pending request and audits it.
- `approve(id, *, by, note=None)` and `deny(id, *, by, note=None)`: decide a pending request.
- `pending() -> list[ApprovalRequest]`: expires stale requests first, then lists pending ones.
- `execute(id, payload, fn) -> T`: runs `fn(payload)` once for an approved, unexpired, matching request.
- `verify_audit() -> (bool, int | None)`: returns the 1-based position of the first bad audit record.
- Stores: `MemoryStore`, `JsonFileStore(path, *, max_bytes=50 * 2**20)`, and the `ApprovalStore` protocol.
- `ApprovalError.code` is one of `not_found`, `already_decided`, `expired`, `not_approved`, `already_consumed`, `payload_mismatch`, `self_approval`, `payload_too_large`, `store_corrupt`, `store_full`, `invalid_argument`.

Limits: payloads are JSON types only, nested at most 32 levels and at most 65,536 bytes canonically; text fields are 1 to 1000 characters; the store holds at most 10,000 requests by default and nothing is evicted; `execute` records the request as consumed before `fn` runs.

Options: `ttl` sets the default lifetime, `allow_self_approval` permits a requester to approve their own request, `id_factory` supplies request ids, and `on_event` receives `event`, `request_id`, `actor` and `status` (never payload values).

## Why not HumanLayer?

HumanLayer is a hosted service. This library is a zero-dependency package that keeps decisions and the audit log in your own process and storage.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model, including what is not defended: decider identity, whole-chain rewrites and multi-process races.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
