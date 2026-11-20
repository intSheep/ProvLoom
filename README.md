# ProvLoom

**Deterministic OCSF v1.3 Security Fact, Provenance Graph & Detection Signal Service for APT Investigation Agents.**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OCSF](https://img.shields.io/badge/OCSF-v1.3.0-0ea5e9.svg)](https://schema.ocsf.io/)

**ProvLoom** (`Provenance` + `Loom`) weaves heterogeneous endpoint, network, firewall, identity, and asset logs into a unified, queryable, and evidence-backed security fact graph — paired with a structured **Detection & Signal Layer** (`pySigma` + OCSF v1.3.0 SQL compiler + 1-hop graph relation matcher) that surfaces traceable investigation entry points (`RuleMatch`, `Signal`, `CandidateGroup`) for downstream APT Investigation Agents without black-box attack judgments.

---

## Why ProvLoom?

- **Immutable Raw Logs & Deterministic Replay**: Append-only raw event store deduplicated via `SHA-256` (`tenant + source + canonical_payload`). Normalized events and the entire entity-relation graph can be deterministically rebuilt from raw logs at any time.
- **OCSF v1.3.0 Fidelity with Zero Silent Drops**: Declarative YAML mappings for `Process (1007)`, `File (1001)`, `Network (4001)`, `Authentication (3002)`, `DNS (4003)`, `Application (6001/6002/6003)`, and `Inventory (5001)`. Unmapped attributes are preserved in `unmapped_fields`, and unsupported log types fall back to `class_uid = 0` (`UNSUPPORTED_PASSTHROUGH`).
- **Scoped & Lifecycle-Aware Identity Resolution**: Resolves `Host`, `Process`, `User`, `File`, `NetworkEndpoint`, `Service`, and `Container` entities without naive name-only merging. Handles per-host PID reuse windows, DHCP/NAT IP leases, provisional isolated identities, and full `EntityMergeAudit` trails.
- **Epistemic Honesty (`DETERMINISTIC` vs `CANDIDATE`)**: Strictly separates verified causal facts from partial-tuple candidates. Aggregates multi-source observations (e.g., Sysmon socket + Zeek `conn` + Firewall 5-tuple flow) onto a single relation while linking **every** supporting raw log in `relation_evidences`.
- **Structured Detection & Epistemic Signal Layer (`v0.2`)**: Compiles Sigma YAML rules (`pySigma` + OCSF v1.3.0 pipeline) into strictly parameterized PostgreSQL/SQLite queries alongside structured 1-hop provenance relation rules. Reports 5-stage rule compatibility (`PARSE_SUCCESS`, `MAPPING_SUCCESS`, `DATA_COVERAGE`, `COMPILE_SUCCESS`, `EXECUTION_SUCCESS`), preserves immutable `RuleMatch` records, and groups entity-scoped `Signal`s and `CandidateGroup`s without mutating the objective fact graph.
- **Built-in Web Inspector Console**: Ships with a 7-view dark/light Web Debug Console for inspecting ingestion health, dead-letter failures, side-by-side `Raw ↔ OCSF ↔ Unmapped` diffs, entity lifecycles, interactive provenance subgraphs, and the **Detection & Signal Workbench** (rule manager, live Sigma-to-SQL sandbox, `RuleMatch`, `Signal`, and `CandidateGroup` browsers).

---

## Architecture

```text
Raw Sources (JSON/JSONL/CSV/Sysmon/Zeek/Firewall/Auth/Assets)
  ──▶ Ingestion (SHA-256 Dedup & Failure Log)
  ──▶ Log Parsers
  ──▶ OCSF v1.3.0 Normalizer (+ Passthrough Fallback)
  ──▶ Scoped Entity Resolver (Host / PID Window / DHCP & NAT / Merge Audit)
  ──▶ Relation Extractor & Cross-Source 5-Tuple Correlator
  ──▶ PostgreSQL 16 (or SQLite for zero-setup local dev)
  ──▶ Scoped Query API (/api/v1/*) & Web Debug Console
```

---

## Quickstart

### 1. Local Zero-Setup Mode (Built-in SQLite)

```bash
make install
make test
make test-acceptance
make api-dev
```

Open `http://127.0.0.1:8000` in your browser and click **"导入内置标准样本" (Seed Built-in Examples)** to explore the live provenance graph and multi-source raw evidence chain.

### 2. PostgreSQL 16 Mode

```bash
export PROVLOOM_DATABASE_URL="postgresql+psycopg://provloom:provloom@localhost:5432/provloom"
make db-up
make db-migrate
provloom seed-examples --tenant default
make api-dev
```

---

## Core Query API

Every query enforces `AccessScope` (`X-Tenant-Id` + optional `X-Allowed-Sources`), `TimeRange`, and hard result/depth bounds:

| Operation | Endpoint | Description |
| :--- | :--- | :--- |
| `search_events` | `POST /api/v1/events/search` | Search OCSF events by time window, source, class, and field values |
| `get_event` | `GET /api/v1/events/{event_id}` | Fetch normalized OCSF event alongside its immutable raw log |
| `search_entities` | `POST /api/v1/entities/search` | Search entities by type, resolution state, or identifier (IP/PID/GUID/Hash) |
| `get_entity` | `GET /api/v1/entities/{entity_id}` | Inspect entity attributes, temporal identifiers, and merge audit records |
| `get_entity_relations` | `GET /api/v1/entities/{entity_id}/relations` | Query inbound/outbound relations (`DETERMINISTIC` by default) |
| `traverse_graph` | `POST /api/v1/graph/traverse` | Cycle-safe multi-hop `WITH RECURSIVE` provenance graph traversal |
| `get_relation_evidence` | `GET /api/v1/relations/{relation_id}/evidence` | Trace any graph edge back to all supporting OCSF & raw log records |
| `list_detection_rules` | `GET /api/v1/detection/rules` | Browse Sigma & Custom rules with 5-stage OCSF/SQL compatibility status |
| `execute_rule_batch` | `POST /api/v1/detection/execute-batch` | Run enabled event & 1-hop relation rules within bounded `TimeRange` |
| `search_rule_matches` | `POST /api/v1/detection/matches/search` | Query immutable `RuleMatch` records with matched values & evidence refs |
| `search_signals` | `POST /api/v1/detection/signals/search` | Query entity-scoped `Signal`s, lifecycle status, and traceable raw evidence |
| `search_candidate_groups` | `POST /api/v1/detection/candidate-groups/search` | Inspect deterministic `CandidateGroup` clusters and unresolved ambiguities |

---

## Repository Structure

```text
├── AGENTS.md                 # Architectural invariants and contributor rules
├── configs/                  # Declarative OCSF YAML mappings & correlation rules
├── docs/                     # PRD (prd.md) and architecture design (architecture.md)
├── migrations/               # Alembic PostgreSQL schema migrations
├── src/provloom/             # Core layered Python package (domain, ingestion, parsing, normalization, entity, graph, storage, query, api)
├── web/                      # TypeScript + React + Cytoscape.js Web Console source
└── tests/                    # Unit, integration, and 10-case PRD acceptance suite
```

## License

Licensed under the [MIT License](LICENSE).
