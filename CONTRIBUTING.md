# Contributing to ProvLoom

Thank you for contributing to **ProvLoom**!

## Architectural Guardrails

Before submitting changes, review [AGENTS.md](AGENTS.md) — in particular the five non-negotiable domain invariants (immutable raw logs, OCSF v1.3.0 fidelity, scoped/temporal entity resolution, strict separation of `DETERMINISTIC` vs `CANDIDATE` relations, and mandatory query scope/time/limit guards).

## Local Verification Checklist

Every pull request must pass all four checks:

```bash
make lint
make typecheck
make test
make test-acceptance
```

## Extending Sources & Mappings

- Prefer adding declarative YAML OCSF field mappings under `configs/mappings/` before writing custom Python mapper classes.
- Keep `src/provloom/storage/postgres/tables.py` synchronized with Alembic migrations under `migrations/versions/`.
