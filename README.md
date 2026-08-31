# Databricks (UC) → Microsoft Fabric Security Migration — Spike

Proof-of-concept toolkit for the spike: *"Assess and validate an automated
approach for extracting and translating Databricks (UC) security
definitions into Microsoft Fabric security constructs."* It reads who
actually holds `SELECT` on a Databricks Unity Catalog view, works out what
data that grant covers (which physical columns, and what row filter),
translates that into Fabric-native OneLake security roles, maps AGS-managed
AD groups onto those roles, and automates deployment through the Fabric
REST API and Azure DevOps pipelines.

**Spike outcome:** Conditional Go — see
[`docs/go-no-go-recommendation.md`](docs/go-no-go-recommendation.md). The
biggest open condition: this toolkit's security model is entirely
view-based (a view's SELECT grant plus its SQL shape). It does **not** read
native Unity Catalog row filters/column masks (`ALTER TABLE ... SET ROW
FILTER/MASK`) — confirm which pattern your estate actually uses before
relying on this for coverage; see
[`docs/limitations.md`](docs/limitations.md#native-unity-catalog-row-filters--column-masks-not-covered).

## How access is determined (read this first)

Two independent things are extracted per view, and joined by view name —
**access never comes from parsing the view's SQL**:

1. **Who** — every principal (AD group or user) holding `SELECT` on the
   view, read directly from Unity Catalog's own grant metadata
   (`information_schema.table_privileges`), or from a plain grants CSV for
   offline/test use. This is the *only* source of access; nothing about a
   principal's access is inferred from the view's `SELECT`/`WHERE` text.
2. **What** — the view's SQL, parsed only to work out what data a grant
   covers:
   - **CLS**: every physical column referenced anywhere in the SELECT list
     — direct or feeding a derived expression — except the derived output
     column itself.
   - **RLS**: the WHERE clause, reproduced **verbatim** (never decomposed),
     against a flattened, derived-column-free column list.

Worked example, straight from the spike's own requirement:

```sql
-- Original view
SELECT a, b, c, d * e AS f FROM table1 WHERE a = 5 AND c = 6;

-- Reformatted (what this toolkit derives for RLS + the CLS column set)
SELECT a, b, c, d, e FROM table1 WHERE a = 5 AND c = 6;
```

`f` never gets a CLS entitlement; `a, b, c, d, e` do, for every principal
this view is granted to. `OR`-joined and nested WHERE clauses are handled
the same way as `AND` — verbatim, by construction, not as a special case
(see `tests/test_view_parser.py::test_or_where_clause_preserved_verbatim`).

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
| Azure DevOps pipeline — Databricks-side extraction | [`pipelines/azure-pipelines-databricks-extract.yml`](pipelines/azure-pipelines-databricks-extract.yml) |
| Azure DevOps pipeline — Fabric-side translate/deploy | [`pipelines/azure-pipelines-security-migration.yml`](pipelines/azure-pipelines-security-migration.yml) |
| Automated tests (28 passing) | [`tests/`](tests/) |

## How it works

```
Unity Catalog SELECT grants  ──────┐   (Databricks-side identity)
                                    ├─► Security Extraction Utility
Databricks/UCM View SQL      ──────┘     (view_parser.py, sqlglot-based;
                                           databricks_client.py for live pulls)
                                              │
                                              ▼
                       JSON / CSV Security Model (cls_entitlements, rls_entitlements)
                                              │
                                              ▼
                       Translator (translator/*.py)              (Fabric-side identity)
                                              │
                                              ▼
              Fabric Data Access Role payloads + AGS→Role mapping
                                              │
                                              ▼
   Azure DevOps Pipelines (Extract [Databricks] → Translate → Validate → Approve → Deploy → Report [Fabric])
                                              │
                                              ▼
                  Fabric APIs (fabric_api/*.py, dry-run by default)
                                              │
                                              ▼
                       Fabric Roles + CLS + RLS Policies
```

See [`docs/architecture.md`](docs/architecture.md) for full diagrams,
including the pipeline-split vs. target-state diagram.

## Quickstart (offline, no Databricks/Fabric connectivity required)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest  # for the test suite

# Run the full pipeline against the sample fixtures (dry-run deploy)
python -m dbx_fabric_security.cli run-all \
  --views tests/fixtures/sample_views.sql \
  --grants tests/fixtures/grants_sample.csv \
  --ags-export tests/fixtures/ags_export_sample.csv \
  --targets tests/fixtures/deploy_targets_sample.json \
  --out-dir out/demo

# Run the test suite
pytest tests/ -v
```

Individual stages are also available: `extract`, `extract-databricks`,
`translate`, `map-roles`, `deploy` (see
`python -m dbx_fabric_security.cli --help`). `extract-databricks` and
`deploy` both default to a network-free dry run; they only call a live API
when given `--execute`/`--apply` respectively, plus a valid token.
`--grants` (a `view,principal,privilege` CSV) is how every offline command
learns who has access — omit it and no CLS/RLS entitlements are produced,
by design (see "How access is determined" above).

## Running the stages separately (Databricks-side vs. Fabric-side)

The toolkit is split so extraction (which needs Databricks access) and
translate/deploy (which needs Fabric access) can run as **separate steps,
under separate identities, on separate schedules** — this is the model to
use today. Consolidating onto one Azure AD identity with both sets of
permissions (see RBAC below) is a later, purely operational change; no code
here needs to change for that.

**1. Extract — runs against Databricks only, no Fabric credentials used:**

```bash
python -m dbx_fabric_security.cli extract-databricks \
  --workspace-url https://adb-1234567890123456.7.azuredatabricks.net \
  --warehouse-id <sql-warehouse-id> \
  --catalog sec \
  --token "$DATABRICKS_TOKEN" \
  --execute \
  --out-dir out/databricks-extract
```

This writes `out/databricks-extract/extracted_views.sql` (the raw,
reconstructed `CREATE VIEW` DDL) **and** `extracted_grants.csv` (every
principal holding SELECT on each view, in the same `view,principal,privilege`
shape as the offline fixture) — together, a durable, reviewable pair of
artifacts you can hand off, commit, or archive — plus
`view_security_definitions.json` (the structured extraction result). Omit
`--execute` to see the request that *would* be made without calling
Databricks at all.

This step can equally run as its own Azure DevOps pipeline
([`pipelines/azure-pipelines-databricks-extract.yml`](pipelines/azure-pipelines-databricks-extract.yml)),
a Databricks Job "Python script" task, or ad hoc from a workstation — it's
a plain REST call (Databricks SQL Statement Execution API), no ODBC driver
or live Spark session required.

**2. Translate / map-roles / deploy — run against Fabric (and read an AGS
export), no Databricks credentials used:**

```bash
python -m dbx_fabric_security.cli translate \
  --views out/databricks-extract/extracted_views.sql \
  --grants out/databricks-extract/extracted_grants.csv \
  --ags-export path/to/ags_export.csv \
  --out-dir out/fabric-translate

python -m dbx_fabric_security.cli deploy \
  --views out/databricks-extract/extracted_views.sql \
  --grants out/databricks-extract/extracted_grants.csv \
  --ags-export path/to/ags_export.csv \
  --targets path/to/deploy_targets.json \
  --bearer-token "$FABRIC_API_TOKEN" \
  --apply \
  --out-dir out/fabric-deploy
```

These take `extracted_views.sql` + `extracted_grants.csv` from step 1 as
plain input — this pipeline never needs to reach Databricks itself. In
Azure DevOps, this is
[`pipelines/azure-pipelines-security-migration.yml`](pipelines/azure-pipelines-security-migration.yml),
which consumes step 1's pipeline artifact via a `resources.pipelines`
reference (or locally-supplied files, for dev/test — see the
`extractSource` parameter in that YAML).

**Target end state:** one Azure DevOps pipeline (or one identity running
both pipelines above back-to-back) using a single Azure AD
application/service principal that has been granted the Databricks-side and
Fabric-side permissions listed below simultaneously. Nothing in the
extraction/translation/deployment code is aware of how many identities are
involved — that's entirely a matter of which token(s) the pipeline supplies
at run time.

## RBAC / permissions required

### Databricks side (Unity Catalog) — for the extraction step

The identity running `extract-databricks` (a PAT-holding user/service
principal, or an Azure AD service principal using an AAD access token —
Databricks accepts either as a bearer token) needs:

| Permission | Why |
|---|---|
| `CAN_USE` on the SQL warehouse referenced by `--warehouse-id` | Required to run any query via the Statement Execution API. |
| `USE CATALOG` on each catalog being scanned | Required to reference `<catalog>.information_schema` at all. |
| `USE SCHEMA` on each schema being scanned (or catalog-level `USE SCHEMA` inherited) | Required to enumerate views within a schema. |
| `SELECT` (or `BROWSE`) on each view being extracted | Unity Catalog only exposes a view's SQL text (`information_schema.views.view_definition`) to a caller who could otherwise query the view. |
| **Ownership of, or `MANAGE`/`ALL PRIVILEGES` on, each view — or account/metastore admin** | This is the one easy to under-provision: `information_schema.table_privileges` only surfaces the grants a caller is entitled to see (broadly: privileges *they* hold or granted, or all privileges if they own the object, hold `MANAGE` on it, or are a metastore/account admin). A caller with only `SELECT` on a view will **not** see other principals' grants on it — the extraction identity needs one of the elevated options above to read the *complete* grantee list, not just its own. |

No write privilege of any kind is required — extraction only ever runs
`SELECT` queries against `information_schema`. Recommended: create a
dedicated Databricks service principal, make it an **owner (or grant it
`MANAGE`) on every catalog/schema in scope** so ownership cascades to the
views within, or — more simply for a broad rollout — grant it
**metastore/account admin** read access if your governance model allows a
read-only admin role; document whichever choice is made, since it's the
permission most likely to be missed in a narrower first attempt. Use this
identity as the pipeline's `DATABRICKS_TOKEN` — do not reuse a human's PAT.

### Fabric side — for the translate/map-roles/deploy steps

The identity running `deploy` (an Azure AD application/service principal
holding a Fabric API bearer token) needs:

| Permission | Why |
|---|---|
| Tenant setting: **"Service principals can use Fabric APIs"** enabled (Fabric Admin Portal → Developer settings) | Fabric blocks all service-principal REST calls by default; a tenant admin must opt this in for the app registration (or its security group) before any live call succeeds. |
| Workspace role of at least **Contributor** on each target workspace (or **Admin**, if the pipeline should also be able to create net-new Lakehouse items rather than only update roles on existing ones) | The Item Data Access Roles API operates at the item level and requires edit rights on the containing workspace/item. |
| An Azure AD app registration with a client secret or certificate, used for the client-credentials (service-principal) OAuth flow against Fabric's token endpoint | This is the credential exchanged for the bearer token passed to `--bearer-token` / `FABRIC_API_TOKEN`. |

No Microsoft Graph / Entra ID group-management permission is required —
this toolkit only *reads* an AGS export file to resolve principal names to
object ids; it never queries or writes group membership directly. (A
future enhancement that reads AGS/Entra live rather than from an export
would additionally need `GroupMember.Read.All` or similar — out of scope
today.)

### Today vs. target state

| | Today (two identities) | Target state (one identity) |
|---|---|---|
| Databricks grants (table above) | On a Databricks-scoped service principal | On one Azure AD app registration |
| Fabric grants (table above) | On a separate Fabric-scoped service principal | On that same Azure AD app registration |
| Pipelines | Two ADO pipelines, chained via a pipeline-resource artifact | One ADO pipeline (or the same two pipelines run by the same identity) |

Getting to the target state is an identity/access-provisioning change
(grant both sets of permissions to one app registration, point both
pipelines' variable groups at its credentials) — it does not require any
change to this toolkit's code.

## Key design assumption (validated)

Derived columns are never granted direct CLS entitlements; the source
columns feeding them are surfaced instead:

```sql
CREATE OR REPLACE VIEW view1 AS
SELECT a * b AS c FROM table1;
-- Every principal granted SELECT on view1 gets CLS entitlements on: a, b
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
