# Contributing to ChainGuard

Thank you for helping improve ChainGuard. The project values small, reviewable changes and evidence-backed security claims.

## Before changing code

1. Read the [architecture](docs/ARCHITECTURE.md).
2. Read the [threat model](docs/THREAT_MODEL.md).
3. Identify which [security property](docs/SECURITY_PROPERTIES.md) the change affects.
4. State the attacker capability and expected secure outcome for security-sensitive changes.

## Development setup

Use Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```

Run the educational example:

```bash
python examples/minimal_gateway.py
```

## Test expectations

- Add positive tests for legitimate behavior.
- Add negative tests for forbidden behavior.
- For gateway checks, assert that the protected adapter is not called after a denial.
- Include malformed-input and replay cases where relevant.
- Add concurrency tests when shared mutable state is involved.
- Never use real credentials or production data in tests.
- Do not claim a security property is complete based only on a unit test.

## Pull request guidance

Keep changes focused. Explain:
- what changed and why;
- which threat or failure mode it addresses;
- assumptions and trade-offs;
- tests added and results observed;
- documentation updated;
- limitations that remain.

Do not add custom cryptographic primitives. Prefer established, reviewed libraries and explicit interfaces.

## Research integrity

Keep experiment inputs, configurations, raw results, and analysis reproducible. Report negative results and unexpected behavior. Do not omit failed attacks or imply that a finite test suite proves universal security.
