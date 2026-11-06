# Security

`trysac-hitl-approval-gate` puts risky agent actions behind a human decision. This page states what the library defends against and what it leaves to the caller. The same model is in the module docstring of `hitl_approval_gate`.

## Threat model

### Defended

| Threat | Defence | Test |
|---|---|---|
| Replay of an approval | The request is recorded as `consumed` before the function runs; a second `execute` raises `already_consumed`. | `test_defends_replay_and_fn_runs_once` |
| Payload substitution after approval | The SHA-256 of the canonical payload is stored in the request and compared on `execute`; a mismatch raises `payload_mismatch` and changes nothing. | `test_defends_payload_substitution` |
| Use of an expired approval | `approve`, `deny` and `execute` refuse at or after `expires_at`; the request becomes `expired`. | `test_defends_expired_approval_execute_at_expires_at` |
| Self-approval | The requester cannot approve their own request unless `allow_self_approval=True`; denial is always allowed. | `test_defends_self_approval` |
| Audit edits | Each record hashes its content and the previous hash; `verify_audit` returns the 1-based position of the first bad record. | `test_defends_audit_edit` |
| Audit deletions | A removed record leaves a sequence gap and a broken chain link at the same position. | `test_defends_audit_deletion` |

### Not defended

- **Decider identity.** The `by` argument is a plain string supplied by the caller. Authenticate the human before calling `approve` or `deny`.
- **Whole-chain rewrites.** Someone who can write the store can recompute every hash and forge a valid chain; removing only the newest records also verifies. Export the latest audit hash to a place the attacker cannot write to and compare it.
- **Multi-process races.** A `threading.Lock` serializes calls inside one process. Two processes sharing one `JsonFileStore` can overwrite each other.

## Input limits

| Input | Limit | Error code |
|---|---|---|
| Canonical payload | 65,536 bytes by default (`max_payload_bytes`) | `payload_too_large` |
| Payload nesting | 32 levels | `invalid_argument` |
| `action`, requester, `by`, `reason`, `note` | 1 to 1000 characters | `invalid_argument` |
| Requests in a store | 10,000 by default (`max_requests`); nothing is evicted | `store_full` |
| `JsonFileStore` file | 50 MiB by default (`max_bytes`) | `store_full` on write, `store_corrupt` on read |

Payloads may contain JSON types only (`None`, `bool`, `int`, finite `float`, `str`, lists, tuples and dicts with string keys). Error messages and `on_event` payloads never contain payload values.

## Canonical payload

The hash is the SHA-256 of `json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)` encoded as UTF-8. This is not RFC 8785 (JCS), so hashes are only stable within Python.

## Reporting a vulnerability

See the repository `SECURITY.md`.
