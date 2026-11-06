# Project record

## Objective

Give agents a human approval gate for risky actions: the exact payload is hashed into a request, a different human decides before a deadline, and an approved, unexpired, unused request with a matching payload runs exactly once. Every transition is recorded in a hash-chained audit log.

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested; in-memory and single-file JSON storage; an in-process lock.
- Out of scope: notifications, quorum (multi-approver) decisions, databases, and authentication of deciders. Anything that needs runtime dependencies or I/O beyond the included stores requires an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 422404 / 91876 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.7263 |

## Factory run u025 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2547 | 79064 | 0 | 4246 | 0.3983 |
| fix-1 | claude-sonnet-5-5 | no | 4 | 610 | 6326 | 24650 | 0.0244 |
| fix-2 | claude-sonnet-5-5 | no | 4 | 637 | 6368 | 24657 | 0.0248 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 622 | 6234 | 39548 | 0.0258 |
| fix-4 | claude-sonnet-5-5 | no | 8 | 1172 | 7366 | 55502 | 0.0357 |
| audit | claude-sonnet-5-5 | no | 12 | 3141 | 27492 | 124054 | 0.1126 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 1405 | 8249 | 41297 | 0.0388 |
| docs | claude-haiku-5-5 | no | 105863 | 5225 | 0 | 0 | 0.0660 |

Total: $0.7263. Prices: Anthropic list prices.
