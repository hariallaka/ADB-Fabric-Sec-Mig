# Databricks (UC) → Microsoft Fabric Security Migration — Spike

Proof-of-concept toolkit for the spike: *"Assess and validate an automated
approach for extracting and translating Databricks (UC) security
definitions into Microsoft Fabric security constructs."* It extracts
Column-Level Security (CLS) and Row-Level Security (RLS) constructs embedded
in Databricks Unity Catalog view definitions, translates them into
Fabric-native OneLake security roles, maps AGS-managed AD groups onto those
roles, and automates deployment through the Fabric REST API and an Azure
DevOps pipeline.

**Spike outcome:** Conditional Go — see
[`docs/go-no-go-recommendation.md`](docs/go-no-go-recommendation.md).

## Deliverables

| Deliverable | Location |
|---|---|
| Technical Assessment Document | [`docs/technical-assessment.md`](docs/technical-assessment.md) |
| Architecture Diagram | [`docs/architecture.md`](docs/architecture.md) |
| Security Role Mapping (AGS → AD Group → Fabric Role) | [`docs/security-role-mapping.md`](docs/security-role-mapping.md) |
| Limitation Analysis | [`docs/limitations.md`](docs/limitations.md) |
| Proof-of-Concept Findings (AC1–AC5 evidence) | [`docs/poc-findings.md`](docs/poc-findings.md) |
| Go/No-Go Recommendation | [`docs/go-no-go-recommendation.md`](docs/go-no-go-recommendation.md) |
| Reference implementation | [`src/dbx_fabric_security/`](src/dbx_fabric_security/) |
| Azure DevOps pipeline | [`pipelines/azure-pipelines-security-migration.yml`](pipelines/azure-pipelines-security-migration.yml) |
| Automated tests (19 passing) | [`tests/`](tests/) |

## How it works

```
Databricks/UCM Views
 ↓
Security Extraction Utility   (extractor/view_parser.py — sqlglot-based)
 ↓
JSON / CSV Security Model     (cls_entitlements, rls_entitlements)
 ↓
Translator                    (translator/*.py)
 ↓
Fabric Data Access Role payloads + AGS→Role mapping
 ↓
Azure DevOps Pipeline         (Extract → Translate → Validate → Approve → Deploy → Report)
 ↓
Fabric APIs                   (fabric_api/*.py, dry-run by default)
 ↓
Fabric Roles + CLS + RLS Policies
```

See [`docs/architecture.md`](docs/architecture.md) for full diagrams.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest  # for the test suite

# Run the full pipeline against the sample fixtures (dry-run deploy)
python -m dbx_fabric_security.cli run-all \
  --views tests/fixtures/sample_views.sql \
  --ags-export tests/fixtures/ags_export_sample.csv \
  --targets tests/fixtures/deploy_targets_sample.json \
  --out-dir out/demo

# Run the test suite
pytest tests/ -v
```

Individual stages are also available: `extract`, `translate`, `map-roles`,
`deploy` (see `python -m dbx_fabric_security.cli --help`). `deploy` never
calls the live Fabric API unless both `--apply` and a `--bearer-token` (or
`FABRIC_API_TOKEN` env var) are supplied.

## Key design assumption (validated)

Derived columns are never granted direct CLS entitlements; the source
columns feeding them are surfaced instead:

```sql
CREATE OR REPLACE VIEW view1 AS
SELECT a * b AS c FROM table1;
-- CLS entitlement candidates: a, b
-- No CLS entitlement generated for: c
```

Verified by `tests/test_view_parser.py::test_derived_column_assumption` and
`tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement`.

## Scope note

This is a **spike**, not a production implementation. Production build-out,
migration of existing security policies, AGS enhancements, and runtime
permission synchronization are explicitly out of scope, per the spike's
requirements — see [`docs/technical-assessment.md`](docs/technical-assessment.md)
and [`docs/limitations.md`](docs/limitations.md) for what was and wasn't
proven.
