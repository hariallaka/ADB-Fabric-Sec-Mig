# Databricks (UC) → Microsoft Fabric Security Migration — Spike

Proof-of-concept toolkit for the spike: *"Assess and validate an automated
approach for extracting and translating Databricks (UC) security
definitions into Microsoft Fabric security constructs."* It reads who
actually holds `SELECT` on a Databricks Unity Catalog view — including each
principal's Azure AD object id — works out what data that grant covers
(which physical columns, and what row filter), translates that into
Fabric-native OneLake security roles, and automates deployment through the
Fabric REST API and Azure DevOps pipelines.

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
**access never comes from parsing the view's SQL, and never from a
separate AD-Group-Sync (AGS) export**:

1. **Who** — every principal (AD group or user) holding `SELECT` on the
   view, read directly from Unity Catalog's own grant metadata
   (`information_schema.table_privileges`), together with that principal's
   Azure AD object id (resolved via the Databricks workspace SCIM API), or
   from a plain grants CSV for offline/test use. This is the *only* source
   of access; nothing about a principal's access is inferred from the
   view's `SELECT`/`WHERE` text, and nothing is cross-referenced against an
   external identity export.
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
| Security Role Mapping (AD Group/principal → Fabric Role) | [`docs/security-role-mapping.md`](docs/security-role-mapping.md) |
| Limitation Analysis | [`docs/limitations.md`](docs/limitations.md) |
| Proof-of-Concept Findings (AC1–AC5 evidence) | [`docs/poc-findings.md`](docs/poc-findings.md) |
| Go/No-Go Recommendation | [`docs/go-no-go-recommendation.md`](docs/go-no-go-recommendation.md) |
| Reference implementation | [`src/dbx_fabric_security/`](src/dbx_fabric_security/) |
| Interactive notebook extraction (logged-in-user identity) | [`notebooks/`](notebooks/) |
| Azure DevOps pipeline — Databricks-side extraction | [`pipelines/azure-pipelines-databricks-extract.yml`](pipelines/azure-pipelines-databricks-extract.yml) |
| Azure DevOps pipeline — Fabric-side translate/deploy | [`pipelines/azure-pipelines-security-migration.yml`](pipelines/azure-pipelines-security-migration.yml) |
| Fabric SQL endpoint path (per-view T-SQL views + super-admin views + role grants) | [`docs/fabric-sql-endpoint-views.md`](docs/fabric-sql-endpoint-views.md) |
| Azure DevOps pipeline — Fabric SQL endpoint path (generate → approve → revoke + deploy via sqlcmd) | [`pipelines/azure-pipelines-fabric-sql-endpoint.yml`](pipelines/azure-pipelines-fabric-sql-endpoint.yml) |
| Automated tests (87 passing) | [`tests/`](tests/) |

## How it works

```
Unity Catalog SELECT grants  ──────┐   (Databricks-side identity)
   + principal object ids (SCIM)   │
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
              Fabric Data Access Role payloads + AD Group/principal → Role mapping
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
  --targets tests/fixtures/deploy_targets_sample.json \
  --out-dir out/demo

# Run the test suite
pytest tests/ -v
```

Individual stages are also available: `extract`, `extract-databricks`,
`grant-catalog-access`, `translate`, `map-roles`, `deploy`,
`generate-fabric-sql` (see
`python -m dbx_fabric_security.cli --help`). `extract-databricks`,
`grant-catalog-access`, and `deploy` all default to a network-free dry run;
they only call a live API when given `--execute`/`--execute`/`--apply`
respectively, plus a valid token. `--grants` (a
`view,principal,principal_object_id,privilege` CSV) is how every offline
command learns who has access — omit it and no CLS/RLS entitlements are
produced, by design (see "How access is determined" above).

## Running the stages separately (Databricks-side vs. Fabric-side)

The toolkit is split so extraction (which needs Databricks access) and
translate/deploy (which needs Fabric access) can run as **separate steps,
under separate identities, on separate schedules** — this is the model to
use today. Consolidating onto one Azure AD identity with both sets of
permissions (see RBAC below) is a later, purely operational change; no code
here needs to change for that.

**0. One-time bootstrap — run once by a catalog owner/admin, not the
extraction identity:**

```bash
python -m dbx_fabric_security.cli grant-catalog-access \
  --workspace-url https://adb-1234567890123456.7.azuredatabricks.net \
  --warehouse-id <sql-warehouse-id> \
  --catalog sec \
  --principal dbx-fabric-extraction-sp \
  --mode owner \
  --token "$ADMIN_TOKEN" \
  --execute
```

Makes the extraction service principal (`--principal`) able to see every
view's definition and every principal's grant in the catalog — without
this, extraction only sees what the identity's *own* grants entitle it to.
See "RBAC / permissions required" below for why this is needed. Run with
`--token` belonging to a catalog owner or metastore admin, never with the
extraction identity's own token (it can't grant itself this privilege —
that's the point).

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
reconstructed `CREATE VIEW` DDL), `extracted_grants.csv` (every principal
holding SELECT on each view, together with its resolved Azure AD object id,
in `view,principal,principal_object_id,privilege` shape), and
`extracted_table_columns.json` (each referenced base table's real column
list, used to correctly attribute an unqualified column in a joined view to
its actual source table — see "Column-to-table attribution" below) —
together, a durable, reviewable set of artifacts you can hand off, commit,
or archive — plus `view_security_definitions.json` (the structured
extraction result). Omit `--execute` to see the request that *would* be
made without calling Databricks at all.

This step can equally run as its own Azure DevOps pipeline
([`pipelines/azure-pipelines-databricks-extract.yml`](pipelines/azure-pipelines-databricks-extract.yml)),
a Databricks Job "Python script" task, or ad hoc from a workstation — it's
a plain REST call (Databricks SQL Statement Execution API + SCIM API), no
ODBC driver or live Spark session required. Prefer to run it interactively
inside a notebook instead, as yourself, with no separate credential at all?
See [`notebooks/`](notebooks/).

**2. Translate / map-roles / deploy — run against Fabric, no Databricks
credentials used:**

```bash
python -m dbx_fabric_security.cli translate \
  --views out/databricks-extract/extracted_views.sql \
  --grants out/databricks-extract/extracted_grants.csv \
  --table-columns out/databricks-extract/extracted_table_columns.json \
  --out-dir out/fabric-translate

python -m dbx_fabric_security.cli deploy \
  --views out/databricks-extract/extracted_views.sql \
  --grants out/databricks-extract/extracted_grants.csv \
  --table-columns out/databricks-extract/extracted_table_columns.json \
  --targets path/to/deploy_targets.json \
  --bearer-token "$FABRIC_API_TOKEN" \
  --apply \
  --out-dir out/fabric-deploy
```

These take the three artifacts from step 1 as plain input — this pipeline
never needs to reach Databricks itself, and the principal object ids it
needs for Fabric role `members` payloads travel inside
`extracted_grants.csv`, not a separate identity file. `--table-columns` is
optional but recommended whenever any view joins tables — see
"Column-to-table attribution" below. In Azure
DevOps, this is
[`pipelines/azure-pipelines-security-migration.yml`](pipelines/azure-pipelines-security-migration.yml),
which consumes step 1's pipeline artifact via a `resources.pipelines`
reference (or locally-supplied files, for dev/test — see the
`extractSource` parameter in that YAML).

**2b. Alternative Fabric side: T-SQL views on the mirrored item's SQL
analytics endpoint.** When several views on one table have different column
lists *and* different row filters, the OneLake role path above can't
represent them without over-exposing data, because it merges them into one
table-level role per principal. `generate-fabric-sql` keeps each view as a
T-SQL view, grants `SELECT` per view to Fabric roles from an AD group →
Fabric role CSV, and builds one combined super-admin view per base table
(union of columns, `OR` of row filters):

```bash
python -m dbx_fabric_security.cli generate-fabric-sql \
  --views out/databricks-extract/extracted_views.sql \
  --grants out/databricks-extract/extracted_grants.csv \
  --table-columns out/databricks-extract/extracted_table_columns.json \
  --role-mapping path/to/ad_group_to_fabric_role.csv \
  --out-dir out/fabric-sql
```

On later runs, add `--previous-state <previous run>/fabric_sql/deployed_state.json`.
That writes a `<catalog>__revoke.sql`, to run before the deploy script, which
revokes grants and role memberships that are no longer in Unity Catalog or the
mapping. To automate the cycle, use
[`pipelines/azure-pipelines-fabric-sql-endpoint.yml`](pipelines/azure-pipelines-fabric-sql-endpoint.yml).

Read [`docs/fabric-sql-endpoint-views.md`](docs/fabric-sql-endpoint-views.md)
before deploying. It lists which views are held back for review, and the
in-tenant checks (ownership chaining, item sharing at Read only) that the
design's security depends on.

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
| **Ownership of, or `ALL PRIVILEGES`/`MANAGE` on, every catalog being scanned — see "One-time bootstrap" above** | This is the one easy to under-provision: `information_schema.views.view_definition` and `information_schema.table_privileges` only surface what the caller is entitled to see. A caller with only `SELECT` on a view sees that view's own definition but **not** other principals' grants on it. Ownership (or `MANAGE`/admin) is what makes the *complete* view list and *complete* grantee list visible, not just the caller's own. `grant-catalog-access` (see step 0 above) sets this up in one command, run once by an existing catalog owner/admin. |
| SCIM read access on the workspace (typically **workspace admin**) | Required for `fetch_principal_directory` to resolve a grantee name to its Azure AD object id via the workspace SCIM API (`/api/2.0/preview/scim/v2/Groups` and `/Users`). Without it, extraction still runs but every principal comes back with an empty `principal_object_id` in `extracted_grants.csv`, flagged unresolved downstream. |

No write privilege of any kind is required for the *recurring* extraction
run — it only ever runs `SELECT` queries against `information_schema` plus
read-only SCIM lookups. (`grant-catalog-access` is the one write operation
in this toolkit, and it's a one-time bootstrap step run by an admin, not
part of the recurring pipeline.) Recommended: create a dedicated Databricks
service principal, run `grant-catalog-access --mode owner` (or
`all_privileges`, if you'd rather not transfer ownership) once per
in-scope catalog, grant it workspace admin for SCIM read access, and use it
as the pipeline's `DATABRICKS_TOKEN` identity — do not reuse a human's PAT.

### Fabric side — for the translate/map-roles/deploy steps

The identity running `deploy` (an Azure AD application/service principal
holding a Fabric API bearer token) needs:

| Permission | Why |
|---|---|
| Tenant setting: **"Service principals can use Fabric APIs"** enabled (Fabric Admin Portal → Developer settings) | Fabric blocks all service-principal REST calls by default; a tenant admin must opt this in for the app registration (or its security group) before any live call succeeds. |
| Workspace role of at least **Contributor** on each target workspace (or **Admin**, if the pipeline should also be able to create net-new Lakehouse items rather than only update roles on existing ones) | The Item Data Access Roles API operates at the item level and requires edit rights on the containing workspace/item. |
| An Azure AD app registration with a client secret or certificate, used for the client-credentials (service-principal) OAuth flow against Fabric's token endpoint | This is the credential exchanged for the bearer token passed to `--bearer-token` / `FABRIC_API_TOKEN`. |

No Microsoft Graph / Entra ID group-management permission is required on
this side — the Fabric-side steps only *read* the `principal_object_id`
column already sitting in `extracted_grants.csv` (resolved earlier, on the
Databricks side); they never call Graph or Entra themselves.

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

## Column-to-table attribution (joins)

A view built on a **single** table has no ambiguity: every column in its
SELECT list — qualified or not — obviously belongs to that one table. A
view that **joins** two or more tables is different: a column the SQL
qualifies (`t1.a`) resolves directly, but a bare, unqualified column (just
`a`) gives the parser (`sqlglot`, which does no schema-aware resolution)
nothing to disambiguate it with — it can't tell on its own whether `a`
came from `table1` or `table2`. Get this wrong and a CLS entitlement gets
granted against the wrong physical table.

This is fixed, not just flagged: an unqualified column in a joined view is
resolved against each candidate table's **real column list** —
`DatabricksApiClient.fetch_table_columns` live (`extract-databricks` runs
this automatically, as an extra pass before the final parse), or
`--table-columns <path/to/json>` offline (`{"catalog.schema.table":
["col1", "col2", ...]}` — see `tests/fixtures/table_columns_sample.json`).
This resolution is deterministic, not a best guess: Databricks/Spark SQL
refuses to `CREATE VIEW` in the first place if an unqualified column is
genuinely ambiguous across the joined tables, so once each table's real
columns are known there is at most one correct answer.

Without a table-columns schema supplied, a joined view's unqualified
columns still get entitlements (nothing is silently dropped) — they just
fall back to the view's first base table (alphabetically), **explicitly
flagged** per column in `unsupported_constructs` rather than resolved
silently, which is what happened before this was addressed. Worked
example (`tests/fixtures/sample_views.sql`,
`sec.sales.v_orders_with_region_name`):

```sql
CREATE OR REPLACE VIEW sec.sales.v_orders_with_region_name AS
SELECT order_id, amount, region_name  -- region_name is unqualified
FROM sec.sales.orders o
JOIN sec.sales.regions r ON o.region = r.region_code;
-- region_name actually lives on `regions`, not `orders`.
```

| | `column_source_tables["region_name"]` | Flagged? |
|---|---|---|
| No `--table-columns` supplied | `sec.sales.orders` (**wrong**) | Yes — explicit per-column warning |
| `--table-columns tests/fixtures/table_columns_sample.json` | `sec.sales.regions` (**correct**) | No |

Verified by `tests/test_view_parser.py::test_unqualified_join_column_misattribution_is_flagged_without_schema`,
`test_unqualified_join_column_resolves_correctly_with_table_columns`, and
`tests/test_cls_translator.py::test_join_column_attributed_to_its_real_table_when_schema_supplied`.

This only affects **CLS** (which table a *column* belongs to). It does not
extend to **RLS** for a multi-table WHERE clause — deciding which table a
cross-table row-filter predicate should become a Fabric row filter *against*
is a materially harder, still-open problem; see
[`docs/limitations.md`](docs/limitations.md#complex-view-definitions-joins).

## Target resolution: tables, not views

**This toolkit never deploys a view to Fabric.** Databricks views are
extraction-only artifacts, read purely to work out what CLS/RLS a table's
grantees should get (see "How access is determined" above); every Fabric
role it builds is scoped to the *physical base table* the view sits on
(`role["table"]`, e.g. `sec.hr.employee`), never to the view itself
(`sec.hr.v_employee_active`). If you're migrating **tables**, not views, to
Fabric — recreating each Databricks base table as a Fabric Lakehouse table
and retiring the views — this is exactly the shape you want: the CLS/RLS
logic a view expressed gets carried over and re-applied directly to its
underlying table's Fabric counterpart.

**If you keep the base table's name identical in Fabric and Databricks**
(a common, recommended migration choice), you get a real simplification for
free: `role_builder.py` already scopes each role's column rule to
`Tables/<bare-table-name>` — just the last segment of the Databricks
qualified name — so as long as that name matches the Fabric Lakehouse
table's name, no per-table configuration is needed for *that* part. The one
place a table still needs to be pointed at a Fabric workspace/Lakehouse
*item* is `--targets` (deploy's target map), and that's where the naming
decision pays off a second time: `--targets` accepts a **schema-level**
default —

```json
{
  "schemas": {
    "sec.finance": {"workspaceId": "...", "itemId": "..."},
    "sec.hr":      {"workspaceId": "...", "itemId": "..."},
    "sec.sales":   {"workspaceId": "...", "itemId": "..."}
  },
  "tables": {
    "sec.sales.order_lines": {"workspaceId": "...", "itemId": "..."}
  }
}
```

— so **one entry per Databricks schema** (mapping it to the Fabric
Lakehouse item that hosts that schema's migrated tables) covers *every*
table in it, instead of listing tables one by one. `"tables"` is for the
exception: a specific table that needs to land in a different Lakehouse
than its schema's default (an exact `"tables"` entry always wins over a
`"schemas"` default for the same table). See
`tests/fixtures/deploy_targets_sample.json` for a worked example, and
`fabric_api/deploy.resolve_table_target` for the resolution logic.

**Nested views are the one case this needs a human for.** A view built on
*another view* (not a table) has a `base_tables` entry that's itself a view
name (e.g. `sec.hr.v_employee_basic`) — under table-only migration, that
name will never exist as a real Fabric table, so any role that would target
it is filtered out before deployment and reported separately
(`Skipped -- these are Databricks VIEWS...`), even if a schema-level
default would otherwise have matched it by name. Resolve the nested view
down to its ultimate physical table before deploying — see
[`docs/limitations.md`](docs/limitations.md) for the general nested-view
gap this falls under.

## Scope note

This is a **spike**, not a production implementation. Production build-out,
migration of existing security policies, and runtime permission
synchronization are explicitly out of scope, per the spike's requirements —
see [`docs/technical-assessment.md`](docs/technical-assessment.md) and
[`docs/limitations.md`](docs/limitations.md) for what was and wasn't
proven.
