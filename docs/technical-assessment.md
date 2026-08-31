# Technical Assessment: Databricks (UC) → Microsoft Fabric Security Translation

**Spike status:** Complete. See [go-no-go-recommendation.md](./go-no-go-recommendation.md) for the outcome.

**Scope covered:** CLS translation, RLS translation, AGS→AD Group→Fabric role
mapping, automation framework, limitation analysis (per the spike's In Scope
list). Production implementation, migration of existing policies, AGS
changes, and runtime permission sync are explicitly out of scope, as they
were for the spike.

## 1. Extraction Approach

Databricks view definitions were treated as the single source of truth for
CLS/RLS logic, consistent with the dynamic-view security pattern used across
Unity Catalog estates that predate (or coexist with) native UC row filters /
column masks. The extraction utility (`extractor/view_parser.py`) uses
[`sqlglot`](https://github.com/tobymao/sqlglot) (Databricks dialect) to parse
`CREATE [OR REPLACE] VIEW ... AS SELECT ...` DDL into an AST, then walks it
to recover:

- **Catalog / Schema / View / base table(s)** from the `CREATE VIEW` target
  and the `FROM`/`JOIN` clauses.
- **Column lineage** for every output column: is it a direct pass-through,
  a masked pass-through, or a *derived* expression (arithmetic, function
  call, aggregate) — and if derived, which source column(s) feed it.
- **Column masks (CLS)** recognized via the standard Databricks dynamic-view
  pattern: `CASE WHEN is_account_group_member('<group>') THEN <col> ELSE
  <redacted-value> END AS <col>`.
- **Row filters (RLS)** recognized from the view's `WHERE` clause, split on
  top-level `AND` into independent predicates and classified into one of:
  - `GROUP_GATE` — a bare `is_account_group_member(...)` call gating the
    whole view for a group, with no per-row attribute tie.
  - `GROUP_ATTRIBUTE` — an attribute compared against a `CASE` expression
    whose branches are keyed by `is_account_group_member(...)`, e.g.
    `WHERE region = CASE WHEN is_account_group_member('sales_region_us')
    THEN 'US' ... END`.
  - `USER_MATCH` — a predicate tied to `current_user()`/`session_user()`
    (ownership-style filters, not group-based).
  - `ATTRIBUTE_MATCH` — a plain data predicate with no identity function.
  - `UNSUPPORTED` — anything the parser cannot confidently classify.

Every extracted `ViewSecurityDefinition` also carries an
`unsupported_constructs` list used to flag views that need manual review
(nested views, `SELECT *`, joins/aggregates/subqueries/unions) rather than
silently mis-translating them. This gives full **catalog → schema → table →
column → AD group → AD group object id → permission** extraction, as
required by scope item 1.

**Catalog/workspace scanning.** This spike's extraction utility operates on
view DDL text (files or a DDL export), which is sufficient to validate the
translation logic end-to-end. A production rollout would add a thin
collection layer on top using the Databricks SDK
(`WorkspaceClient.tables.list()` / `INFORMATION_SCHEMA.VIEWS`) to pull
`view_definition` text for every view in scope directly from Unity Catalog,
feeding the same `parse_view()` entry point unchanged. That collection layer
was not built in this spike (no live Databricks workspace credentials were
in scope), but the interface it needs to satisfy is a single function:
`str view_ddl -> ViewSecurityDefinition`, which is already implemented and
tested.

## 2. Translation Framework

### CLS translation (`translator/cls_translator.py`)

Each `ColumnMask` becomes a `PERMIT` entitlement: `(table, column, AD group)`.
Each *derived* output column contributes its leaf source columns as
`DERIVED_SOURCE` entitlement candidates — explicitly **without** an
entitlement on the derived column itself, and without inferring a group for
the source columns unless one was already expressed via an explicit mask.
This directly implements the spike's key design assumption:

```sql
CREATE OR REPLACE VIEW view1 AS
SELECT a * b AS c FROM table1;
```

produces CLS-eligible entries for `a` and `b`, and **none** for `c`. This was
validated by `tests/test_view_parser.py::test_derived_column_assumption` and
`tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement`,
both passing against this exact pattern (see
[poc-findings.md](./poc-findings.md)).

Plain pass-through columns with no mask are still recorded (as
`DEFAULT_VISIBLE`) to keep the entitlement report a complete, auditable
column inventory per view — not just a list of restricted columns.

### RLS translation (`translator/rls_translator.py`)

The core translation insight: Databricks dynamic views check group
membership *inline*, inside the predicate. Fabric ties a row-filter
predicate to a **role**, and role membership is a separate, declarative
concept. So translation does not try to reproduce
`is_account_group_member()` calls inside a Fabric predicate — it strips the
membership check out and produces one `(AD group, predicate)` pair per
group, where the *group itself* becomes the role's membership and the
predicate becomes the role's row filter:

- `GROUP_GATE` → predicate `TRUE` (full row visibility, gated purely by role
  membership).
- `GROUP_ATTRIBUTE` → one predicate per group, e.g. `sales_region_us` →
  `region = 'US'`. Self-referential branches (e.g. `THEN region`, meaning
  "no restriction for this group") normalize to `TRUE`.
- `USER_MATCH` → rewritten to a per-user dynamic predicate
  (`current_user()` → `USERPRINCIPALNAME()`) and flagged
  `requires_validation` — Fabric's exact per-user dynamic function needs to
  be confirmed against the current API (see §4 and Limitations).
- `ATTRIBUTE_MATCH` / `UNSUPPORTED` → surfaced for manual review; these have
  no identity function to drive automatic role assignment.

### Role construction (`translator/role_builder.py`)

CLS and RLS entitlements are merged into one Fabric Data Access Role payload
per `(table, AD group)` pair — matching Fabric's OneLake Data Access Roles
model, where a role scopes a set of Entra members to a path (table/folder)
with column and row decision rules. See [poc-findings.md](./poc-findings.md)
for a real generated payload.

## 3. Security Mapping Design

See [security-role-mapping.md](./security-role-mapping.md) for the full
AGS → AD Group → OneLake Security Role → OneLake object model, and
`mapping/role_mapper.py` for the implementation. In short: AGS remains the
single source of truth for group membership and is never written to by this
toolkit; the mapping utility only *reads* an AGS export to resolve AD group
names to Entra object ids, and joins that onto the roles generated by
`role_builder.py` to produce a governance-reviewable mapping table (JSON and
CSV).

## 4. Fabric API Assessment

| Capability needed | Fabric API | Assessment |
|---|---|---|
| Create/update OneLake role scoped to a table/folder, with row filter + column rules | **Item Data Access Roles API** (`PUT /v1/workspaces/{workspaceId}/items/{itemId}/dataAccessRoles`, public preview at time of writing) | Best available fit for the OneLake Security Role concept in the spike's scope diagram. `fabric_api/client.py` implements `get_data_access_roles` / `put_data_access_roles` against this shape. **The exact request/response schema (decision-rule structure, row-filter field name/expression grammar, column-rule shape) needs to be re-validated against the current Fabric REST API reference before any live call** — this API was in active preview and field names used here (`decisionRules`, `columnRules`, `rowFilters`) are a best-effort approximation pending that validation, not a confirmed contract. |
| List Lakehouse items to resolve table → workspace/item targets | Core Items API (`GET /v1/workspaces/{workspaceId}/items`) | Stable, low risk. `client.list_workspace_items()` implemented. |
| Authenticate service-principal calls | Azure AD app registration, client-credentials flow, Fabric API permission scope | Standard AAD app registration pattern; no blocker identified, but requires the target tenant's Fabric admin to enable service-principal API access (a tenant setting) before this can run non-interactively in a pipeline. |
| Per-user dynamic row-filter predicate (for `USER_MATCH` views) | Not confirmed | Needs a validation spike against a live Fabric workspace: does the Data Access Roles row-filter grammar support a "calling principal" function comparable to Databricks' `current_user()`? Tracked as a limitation (§ Limitations). |

**Recommendation:** before any production build-out, run a short technical
validation pass (a few hours, not a spike) against a live Fabric tenant:
call `GET dataAccessRoles` on a real Lakehouse item to confirm the current
response schema, then adjust `role_builder.py`'s payload shape and
`fabric_api/client.py` to match exactly. The translation logic upstream of
that payload (extraction, CLS/RLS entitlement modeling) does not need to
change regardless of the outcome — only the final serialization step does,
which is deliberately isolated in `role_builder.py` for that reason.

## 5. Automation Workflow

`Extract → Translate → Validate → Approval Gate → Deploy → Report`,
implemented as both a CLI (`dbx_fabric_security.cli`, subcommands
`extract`/`translate`/`map-roles`/`deploy`/`run-all`) and an Azure DevOps
pipeline (`pipelines/azure-pipelines-security-migration.yml`) that chains
those CLI calls across stages, publishes every intermediate artifact, runs
the unit test suite as a validation gate, and requires a manual
environment-approval check (`fabric-security-prod`) before any stage that
can call the Fabric API with `--apply`. Every deploy defaults to a dry run;
`--apply` plus a bearer token are both required to make a live call, and the
deploy step is a full-replace `PUT` that first reads existing roles and
preserves any role not owned by this toolkit's naming convention
(`role_<table>_<group>`), so manually-authored Fabric roles are never
clobbered.

## 6. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Fabric Data Access Roles API schema changes during/after preview | Schema is isolated to `role_builder.py` / `fabric_api/client.py`; extraction and entitlement modeling are API-agnostic and don't need to change. |
| SQL parsing misses a security pattern used in production views (e.g. a variant masking idiom) | Parser is conservative: unrecognized constructs are captured in `unsupported_constructs` rather than silently dropped or mis-translated; every view report is inspectable before any deploy. |
| Derived-column assumption doesn't match a real, more complex production view (e.g. a derived column built from *masked* source columns) | Explicitly tested and documented (see §2); flagged in Limitations for extension. |
| Automated deploy overwrites a manually-created Fabric role | Deploy only manages roles matching its own naming convention and preserves everything else; full plan is diffed and reported before apply. |
| AD group referenced in a Databricks view has no AGS mapping | Reported as `unresolvedAdGroupObjectId` in role/mapping output; role is still generated but deploy should be blocked on this until resolved (see pipeline's Validate stage). |
| Nested/complex views produce incomplete lineage | Detected and flagged for manual review rather than translated with false confidence (see Limitations). |

## 7. Known Limitations

See [limitations.md](./limitations.md) for the full analysis (AC5).

## 8. Success Criteria — Status

| Success Criterion | Status |
|---|---|
| A viable approach exists for translating Databricks CLS and RLS controls into Fabric | **Met** — demonstrated end-to-end against representative view patterns, see PoC findings |
| Required Fabric APIs are identified and validated | **Partially met** — API identified (Item Data Access Roles); exact schema requires a short live-tenant validation pass before production build |
| AGS-based identity governance remains authoritative | **Met** — toolkit only reads AGS exports, never writes |
| End-to-end automation can be executed through Azure DevOps pipelines | **Met** — pipeline implemented with approval gate |
| All assumptions, risks, and limitations are documented for the UCM SAD | **Met** — this document set |
