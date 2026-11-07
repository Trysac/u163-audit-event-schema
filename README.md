# audit-event-schema

[![PyPI version](https://img.shields.io/pypi/v/trysac-audit-event-schema)](https://pypi.org/project/trysac-audit-event-schema/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-audit-event-schema)](LICENSE)
[![CI](https://github.com/Trysac/u163-audit-event-schema/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u163-audit-event-schema/actions/workflows/ci.yml)

A strict audit event model with canonical JSON: who did what to which target with what outcome, validated fields, UTC millisecond time and a refusal of secret attributes

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-audit-event-schema
# or
uv add trysac-audit-event-schema
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import audit_event_schema

# normalize() trims surrounding whitespace and lower-cases the text.
print(audit_event_schema.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    audit_event_schema.normalize("   ")
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
