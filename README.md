# hitl-approval-gate

[![PyPI version](https://img.shields.io/pypi/v/trysac-hitl-approval-gate)](https://pypi.org/project/trysac-hitl-approval-gate/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-hitl-approval-gate)](LICENSE)
[![CI](https://github.com/Trysac/u025-hitl-approval-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u025-hitl-approval-gate/actions/workflows/ci.yml)

Human approval gate for agent actions with side effects: payload-bound requests, expiry, single use, no self-approval and a hash-chained audit log

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-hitl-approval-gate
# or
uv add trysac-hitl-approval-gate
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import hitl_approval_gate

# normalize() trims surrounding whitespace and lower-cases the text.
print(hitl_approval_gate.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    hitl_approval_gate.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
