# AGENTS.md

Repository guide and architectural invariants for coding agents and contributors working on **ProvLoom**.

## 1. Mission & Non-Goals

ProvLoom is a deterministic, traceable **Security Fact & Provenance Graph Data Service** built for downstream APT Investigation Agents, paired with a lightweight Web Debug Console.

- **In Scope (MVP):** Multi-source log ingestion, parsing, OCSF v1.3.0 normalization, entity identity resolution, provenance relation extraction, PostgreSQL persistence, read-only Query API, Ops/Debug API, and Web Inspector UI.
- **Out of Scope:** SIEM rule/Sigma detection engine, IOC intelligence platform, LLM semantic reasoning, attack hypothesis management, Agent runtime, automated SOAR response.

## 2. Non-Negotiable Domain Invariants

Every change MUST preserve these five guarantees:

1. **Immutable Raw Log & Zero Silent Drop**
   - `raw_events` is append-only and deduplicated via `UNIQUE (tenant_scope, source_id, raw_fingerprint)` (`SHA-256` over tenant, source, and canonical payload).
   - Malformed records or pipeline errors MUST be recorded in `pipeline_failures`.
   - Parsed events without a dedicated OCSF class mapper MUST fall back to `class_uid = 0` (`UNSUPPORTED_PASSTHROUGH`), never silently discarded.
   - Derived tables (`normalized_events`, `entities`, `relations`, `relation_evidences`) MUST be deterministically rebuildable from `raw_events`.

2. **OCSF v1.3.0 Standard Fidelity**
   - Preserve `ocsf_version` (`"1.3.0"`), `metadata.original_uid`, and `raw_event_id` on every normalized event.
   - Preserve unmapped source attributes in `unmapped_fields` / `ocsf_payload.unmapped`.

3. **Scoped & Lifecycle-Bounded Entity Resolution**
   - Never merge entities by bare name alone (e.g., `cmd.exe`, `admin`, `nginx`).
   - `PROCESS` without a globally unique `ProcessGuid` MUST be scoped by `(host_entity_id, pid, valid_from, valid_to)` so PID reuse spawns a distinct entity.
   - `HOST` IP bindings must respect DHCP/NAT validity windows; isolated or ambiguous identities remain `PROVISIONAL`.
   - Every entity merge MUST write an immutable `EntityMergeAudit` record with `merge_rule_id`, `match_basis`, and `evidence_event_ids`.

4. **Epistemic Separation (`DETERMINISTIC` vs `CANDIDATE`)**
   - Never promote pure timestamp proximity into a `DETERMINISTIC` causal relation.
   - Cross-source network correlation (Endpoint ↔ Firewall/Zeek) is `DETERMINISTIC` only when host IP ownership is verified (no unknown SNAT), the 5-tuple matches, and `|Δt| <= max_clock_skew_seconds`.
   - Repeated logs of the same interaction may aggregate onto one `Relation`, but EVERY supporting event MUST be linked in `relation_evidences`.

5. **Mandatory Query Guards**
   - Every `QueryService` method MUST enforce `AccessScope` (`tenant_id` + `allowed_sources`), `TimeRange`, and bounded result limits (`PageSpec.limit <= max_limit`, `max_depth <= 6`, `max_nodes`, `max_edges`).

## 3. Architecture & Dependency Direction

```text
api / cli  ──▶  query / pipeline  ──▶  ingestion / parsing / normalization / entity / graph  ──▶  domain  ◀──  storage
```

- `src/provloom/domain/`: Pure models, enums, value objects, and exceptions. **Zero SQLAlchemy, FastAPI, or IO imports.**
- `src/provloom/query/`: Strictly read-only query contracts shared by external Agents and the Web UI (`/api/v1/*`).
- `src/provloom/api/v1/ops.py`: Operational ingestion, retry, and replay endpoints dedicated to CLI and Web Debug Console (`/api/v1/ops/*`).
- Future MCP Server integration MUST live outside core `provloom` as a thin adapter over `QueryService` or REST API.

## 4. Coding & Maintenance Standards

- **Concise Code, Key Comments Only:** Keep functions focused and small. Do NOT add boilerplate docstrings or comments that restate identifiers/types. Comment **only** non-obvious domain invariants, edge cases, SQL index trade-offs, or protocol subtleties.
- **Strict Typing:** Maintain `from __future__ import annotations` and full type annotations in Python (`mypy --strict`) and TypeScript (`strict: true`).
- **Config-Driven Mapping First:** Prefer declarative YAML mappings in `configs/mappings/` for field translations; add Python mappers only for complex structural transforms.
- **Schema Sync:** Keep `src/provloom/storage/postgres/tables.py` and `migrations/versions/` strictly synchronized.
- **Web UI (`web/`):**
  - Keep `web/src/api/types.ts` synchronized with backend OpenAPI schemas.
  - Visually distinguish `DETERMINISTIC` relations (solid edges) from `CANDIDATE` relations (dashed amber edges) and `PROVISIONAL` entities (dashed border) in Cytoscape.js.
  - **Browser Support:** Target Baseline Widely Available web platform features; allow Newly Available features only with feature detection and custom fallbacks adding `<= 20` lines and zero external dependencies.

## 5. Development Workflow & Commands

| Task | Command |
| :--- | :--- |
| Install Python + dev deps | `make install` |
| Start local PostgreSQL 16 | `make db-up` |
| Apply DB migrations | `make db-migrate` |
| Lint & format check | `make lint` |
| Static type check (Python + Web) | `make typecheck` |
| Run unit & integration tests | `make test` |
| Run PRD acceptance suite (`AC-01`..`AC-10`) | `make test-acceptance` |
| Run backend API in dev mode | `make api-dev` |
| Run Web Debug Console in dev mode | `make web-dev` |

## 6. Milestone Progression & Acceptance Gate

Implement incrementally along PRD milestones (`M1` Skeleton → `M2` Ingest/Parse → `M3` OCSF → `M4` Entity → `M5` Graph → `M6` Storage/API/Web → `M7` E2E Acceptance). Every feature PR/commit touching `M2`–`M7` should turn the corresponding acceptance cases in `tests/acceptance/test_prd_acceptance_matrix.py` green without breaking idempotency (`AC-08`) or non-forced-merge (`AC-09`) guarantees.
