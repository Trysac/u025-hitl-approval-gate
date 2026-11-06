# Testing

## Running

```sh
uv run pytest --cov=hitl_approval_gate   # tests with coverage report
uv run python scripts/check.py           # every gate, as CI and the factory run it
```

## Policy

- Branch coverage of `src/hitl_approval_gate` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import hitl_approval_gate`) and assert observable effects: return values, raised error codes and stored state.
- Each defended threat in [SECURITY.md](SECURITY.md) has one test named after it.
- Each bug fix starts with a failing test that reproduces it.
- Tests are deterministic: a fake clock, no network, no dependence on test order.

## Layout

`tests/test_<module>.py` mirrors each public module. Shared fixtures go in `tests/conftest.py`.
