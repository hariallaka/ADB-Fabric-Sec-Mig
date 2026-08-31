# Technical Assessment: Databricks (UC) → Microsoft Fabric Security Translation

**Spike status:** Complete. See [go-no-go-recommendation.md](./go-no-go-recommendation.md) for the outcome.

**Scope covered:** CLS translation, RLS translation, AD Group/principal→Fabric
role mapping, automation framework, limitation analysis (per the spike's In
Scope list). Production implementation, migration of existing policies, and
runtime permission sync are explicitly out of scope, as they were for the
spike.

## 1. Extraction Approach

Access is driven **entirely by Unity Catalog's actual SELECT grants on a
view** — never by parsing identity-check logic (e.g. a masking `CASE`
expression) out of the view's SQL. The view's SQL is only used to work out
*what data* a grant covers. Concretely, extraction produces two independent
pieces of information per view, which are then joined by view name:

1. **Grantees** — every principal (AD group or user) holding `SELECT` on
   the view, plus that principal's Azure AD object id. Sourced from
   `information_schema.table_privileges` joined to `information_schema.views`
   for the grantee names (live, via `DatabricksApiClient.fetch_view_grants`),
   with object ids resolved separately via the workspace SCIM API
   (`fetch_principal_directory`, checking Groups then Users for each unique
   name); or from a plain CSV (`view,principal,principal_object_id,privilege`)
   for offline/test use (`extractor/grants.py`). This is never inferred from
   the view's SQL, and never cross-referenced against a separate identity
   export — see the note below.
2. **View shape** — the view's `CREATE VIEW ... AS SELECT ...` DDL, parsed
   with [`sqlglot`](https://github.com/tobymao/sqlglot) (Databricks
   dialect) in `extractor/view_parser.py`, to work out:
   - **Flattened source columns**: every physical column referenced
     anywhere in the SELECT list — whether selected directly or used inside
     a derived expression — with the derived output alias itself excluded.
     `SELECT a, b, a * b AS c` yields `[a, b]`; `c` never appears.
   - **FROM/JOIN clause and WHERE clause**, kept verbatim (not decomposed)
     so a flattened "reformatted" SELECT can be reconstructed for RLS.
   - Structural flags: `is_complex` (JOIN/GROUP BY/window/subquery/UNION),
     `references_views` (nested views), and `SELECT *` detection — these
     don't block extraction but mark a view for manual review.

**A note on what changed during this spike.** An earlier iteration of this
toolkit tried to *infer* both the permission model and the row-filter logic
by pattern-matching `CASE WHEN is_account_group_member(...) ...`
expressions inside view SQL (the classic Databricks "dynamic view" idiom).
That approach was replaced with the grant-based model described above,
because it conflated two independent things — who has SELECT (a Unity
Catalog grant, queryable directly and authoritatively) and what the SELECT
returns (the view's SQL) — into a single fragile SQL-pattern-matching
problem. The current approach is both simpler and more correct: it reads
the actual grant instead of guessing intent from SQL text.

## 2. Translation Framework

### CLS translation (`translator/cls_translator.py`)

The rule is a direct cross-product: every principal granted SELECT on a
view gets a `PERMIT` entitlement on every column in that view's flattened
source-column list. No per-column distinction is made — a view's SELECT
grant is all-or-nothing per column, matching how Unity Catalog's own view
grant works (there is no partial-column SELECT grant on a view; the view
definition itself is what restricts which columns are exposed).

This directly implements the spike's key design assumption:

```sql
CREATE OR REPLACE VIEW view1 AS
SELECT a * b AS c FROM table1;
```

Every grantee of `view1` gets a CLS entitlement on `a` and `b`; **none** on
`c`. Validated by
`tests/test_view_parser.py::test_derived_column_assumption` and
`tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement`
(see [poc-findings.md](./poc-findings.md)).

### RLS translation (`translator/rls_translator.py`)

Every principal granted SELECT on a view gets the view's WHERE clause as
its Fabric row filter, **carried through verbatim**. It is never
decomposed, rewritten, or interpreted — whatever boolean expression the
view author wrote (including nested `AND`/`OR`/`NOT`) is what gets
reproduced. A view with no WHERE clause gets an unrestricted (`TRUE`) row
filter. The toolkit also emits a "reformatted SELECT" per view — the
flattened column list against the same FROM/WHERE — matching the pattern
requested in the spike:

```sql
-- Original view
SELECT a, b, c, d * e AS f FROM table1 WHERE a = 5 AND c = 6;

-- Reformatted (RLS-ready)
SELECT a, b, c, d, e FROM table1 WHERE a = 5 AND c = 6;
```

OR-joined predicates are a first-class case, not a special one — because
nothing is decomposed, `WHERE region = 'US' OR region = 'CA'` and
`WHERE (region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH'` both
round-trip unchanged. See
`tests/test_view_parser.py::test_or_where_clause_preserved_verbatim` and
`tests/test_rls_translator.py::test_or_predicate_carried_through_verbatim_for_every_grantee`.

### Role construction (`translator/role_builder.py`)

CLS and RLS entitlements are merged into one Fabric Data Access Role
payload per `(table, principal)` pair — matching Fabric's OneLake Data
Access Roles model, where a role scopes a set of Entra members to a path
(table/folder) with column and row decision rules. See
[poc-findings.md](./poc-findings.md) for a real generated payload.

## 3. Security Mapping Design

See [security-role-mapping.md](./security-role-mapping.md) for the full
AD Group/principal → OneLake Security Role → OneLake object model, and
`mapping/role_mapper.py` for the implementation. No separate identity
export is involved: a principal's Azure AD object id is resolved once, at
extraction time, directly from Databricks (via the workspace SCIM API) and
travels with the grant data all the way through to the Fabric role payload;
`mapping/role_mapper.py` only flattens the already-resolved roles into a
reviewable report.

## 4. Fabric API Assessment

| Capability needed | Fabric API | Assessment |
|---|---|---|
| Create/update OneLake role scoped to a table/folder, with row filter + column rules | **Item Data Access Roles API** (`PUT /v1/workspaces/{workspaceId}/items/{itemId}/dataAccessRoles`, public preview at time of writing) | Best available fit for the OneLake Security Role concept in the spike's scope diagram. `fabric_api/client.py` implements `get_data_access_roles` / `put_data_access_roles` against this shape. **The exact request/response schema needs to be re-validated against the current Fabric REST API reference before any live call** — field names used here (`decisionRules`, `columnRules`, `rowFilters`) are a best-effort approximation, not a confirmed contract. |
| List Lakehouse items to resolve table → workspace/item targets | Core Items API (`GET /v1/workspaces/{workspaceId}/items`) | Stable, low risk. `client.list_workspace_items()` implemented. |
| Authenticate service-principal calls | Azure AD app registration, client-credentials flow, Fabric API permission scope | Standard AAD app registration pattern; requires the target tenant's Fabric admin to enable service-principal API access before this can run non-interactively in a pipeline. |
| Read Unity Catalog SELECT grants | Databricks Statement Execution API against `information_schema.table_privileges` | Implemented (`DatabricksApiClient.fetch_view_grants`). Standard SQL, no special API needed beyond warehouse access; requires the catalog-ownership bootstrap (§ RBAC) to see every grant, not just the caller's own. |
| Resolve a grantee name to its Azure AD object id | Databricks workspace SCIM API (`/api/2.0/preview/scim/v2/Groups`, `/Users`) | Implemented (`DatabricksApiClient.fetch_principal_directory`). Requires the caller to have SCIM read access (typically workspace admin); unresolved names are flagged rather than dropped. |

**Recommendation:** before any production build-out, run a short technical
validation pass (a few hours, not a spike) against a live Fabric tenant:
call `GET dataAccessRoles` on a real Lakehouse item to confirm the current
response schema, then adjust `role_builder.py`'s payload shape and
`fabric_api/client.py` to match exactly. The translation logic upstream of
that payload does not need to change regardless of the outcome — only the
final serialization step does, which is deliberately isolated in
`role_builder.py` for that reason.

## 5. Automation Workflow

`Extract (Databricks) → Translate → Validate → Approval Gate → Deploy
(Fabric) → Report`, implemented as both a CLI (`dbx_fabric_security.cli`,
subcommands `extract`/`extract-databricks`/`translate`/`map-roles`/`deploy`)
and two Azure DevOps pipelines — one Databricks-only, one Fabric-only, per
README.md's "Running the stages separately" — chained via a pipeline
artifact. Every deploy defaults to a dry run; `--apply` plus a bearer token
are both required to make a live call, and the deploy step is a
full-replace `PUT` that first reads existing roles and preserves any role
not owned by this toolkit's naming convention (`role_<table>_<principal>`),
so manually-authored Fabric roles are never clobbered.

## 6. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Fabric Data Access Roles API schema changes during/after preview | Schema is isolated to `role_builder.py` / `fabric_api/client.py`; extraction and entitlement modeling are API-agnostic and don't need to change. |
| A principal's Azure AD object id can't be resolved via SCIM (extraction identity lacks SCIM read access, or the principal is neither a Databricks group nor user) | Reported as `unresolvedPrincipalObjectId` in role/mapping output; role is still generated but deploy should be blocked on this until resolved (see pipeline's Validate stage). |
| Extraction identity can't see the *complete* grantee list on a view (only `SELECT`, not ownership/`MANAGE`/admin) | `information_schema.table_privileges` silently omits grants the caller isn't entitled to see rather than erroring — mitigated by the one-time `grant-catalog-access` bootstrap step making the extraction identity a catalog owner (see README RBAC section). |
| Nested/complex views produce an incomplete flattened column list or an incomplete row filter | Detected and flagged for manual review rather than translated with false confidence (see Limitations). |
| Automated deploy overwrites a manually-created Fabric role | Deploy only manages roles matching its own naming convention and preserves everything else; full plan is diffed and reported before apply. |
| A view's WHERE clause references a column not exposed in the SELECT list | The WHERE clause is reproduced verbatim regardless — Fabric's row filter, like the original Databricks view, can filter on a column it doesn't return. No special handling needed. |

## 7. Known Limitations

See [limitations.md](./limitations.md) for the full analysis (AC5).

## 8. Success Criteria — Status

| Success Criterion | Status |
|---|---|
| A viable approach exists for translating Databricks CLS and RLS controls into Fabric | **Met** — demonstrated end-to-end against representative view patterns, see PoC findings |
| Required Fabric APIs are identified and validated | **Partially met** — API identified (Item Data Access Roles); exact schema requires a short live-tenant validation pass before production build |
| Identity governance stays read-only and authoritative in Databricks/Entra | **Met** — toolkit only reads Unity Catalog grants + SCIM directory data, never writes membership; the one write it performs (`grant-catalog-access`) is a one-time, admin-run, catalog-level access grant, not an identity change |
| End-to-end automation can be executed through Azure DevOps pipelines | **Met** — pipelines implemented with approval gate |
| All assumptions, risks, and limitations are documented for the UCM SAD | **Met** — this document set |
