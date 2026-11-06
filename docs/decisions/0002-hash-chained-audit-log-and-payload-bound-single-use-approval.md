# Hash-chained audit log and payload-bound single-use approvals with atomic commits

Status: accepted (generated, pending human review)

## Context

Agents that trigger side effects need human approval that cannot be replayed, swapped to a different payload, used after its deadline, or self-granted, and decisions must leave a tamper-evident trail. The library has zero dependencies, must work with an in-memory store and a single JSON file, and must never leak payload values through errors, logs or events.

## Decision

A request stores the SHA-256 of the canonical JSON payload. A single state machine (pending to approved, denied or expired; approved to consumed or expired) is checked in a fixed order under a threading.Lock. Execute records the request as consumed before the function runs, and the function runs outside the lock. Every transition appends an audit record whose hash covers its fields and the previous hash, starting from 64 zeros; verify_audit returns the 1-based position of the first bad record. The built-in stores expose commit(req, record) so the request and its audit record are written together; JsonFileStore does this with one fsynced temporary file and os.replace, and re-reads the file on every operation. Payloads are validated by a bounded walker (depth 32, node and character budget) before serialization.

## Consequences

Replay, payload swaps, expired approvals, self-approval and audit edits or deletions are detected and tested. The file store is O(file size) per operation, which is acceptable under its 50 MiB cap. Whole-chain rewrites, tail truncation, caller-supplied decider identity and multi-process races are not defended and are documented. Hashes are only stable within Python because the canonical form is json.dumps and not RFC 8785. Third-party stores without commit fall back to two writes and lose atomicity.
