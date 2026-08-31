# Limitation Analysis (AC5)

Validated against the scope's named scenarios plus additional gaps found
while building and testing the extraction/translation logic.

## Derived columns

**Status: handled per the spike's key design assumption, validated by
tests.** `a * b AS c` traces `c` back to leaf source columns `a`/`b`; `c`
never receives a direct CLS entitlement, and `a`/`b` are surfaced as
`DERIVED_SOURCE` candidates for review (not auto-granted, since no explicit
group was expressed for them).

**Gap:** a derived column built from an *already-masked* source column
(e.g. `CASE WHEN is_account_group_member('g') THEN salary ELSE NULL END AS
masked_salary`, then a second view does `masked_salary * 1.1 AS
adjusted_salary`) is not resolved across view boundaries — see "Nested
views" below. Within a single view, if a derived expression combines a
masked column with a plain column, the current parser only classifies
top-level `CASE` masks and top-level derived expressions; a derived
expression that *contains* a mask sub-expression (e.g. `(CASE WHEN ... THEN
salary ELSE 0 END) * 1.1 AS adj`) is treated as derived (correct — no
entitlement on `adj`) but the embedded mask is not separately extracted as
its own `ColumnMask`. **Mitigation:** flag this shape explicitly in a future
iteration by walking derived expressions for embedded `CASE` masks, not just
top-level ones.

## Complex view definitions

**Status: detected and flagged, not blindly translated.** Any view with a
`JOIN`, `GROUP BY`, window function, subquery, or `UNION` is marked
`is_complex = true` and added to `unsupported_constructs`; lineage/mask/row
filter extraction still runs on a best-effort basis (and was shown to work
correctly for a straightforward join+aggregate example in the PoC), but
output for such views should be treated as a starting point for manual
review, not an auto-deployable result. **Rationale for not attempting full
correctness:** correctly attributing a WHERE-clause security predicate or a
masked column back to a single physical base table becomes ambiguous once
multiple tables are joined (which table does the row filter really apply to?
does a column mask on the joined output need to become two per-table roles,
one for each side of the join?) — this requires case-by-case design
decisions best made by a data engineer reviewing the flagged view, not a
fully automated rule.

## Nested views

**Status: detected, not resolved.** A view built on another view (e.g.
`v_employee_gated_export` selecting from `v_employee_gated`) is flagged via
`references_views` / `unsupported_constructs`. The security definition of
the base view is **not** currently composed into the dependent view's
extraction result — i.e. `v_employee_gated_export`'s row filter
(`export_team`) is captured, but `v_employee_gated`'s own filter
(`all_employees_view`) is not automatically inherited/merged into it.
**Mitigation for production:** resolve nested views in dependency order
(topological sort over `references_views`), composing a base view's
row filters as additional `AND` predicates and its column masks as
additional constraints on the dependent view's entitlements, before
translation. This is a straightforward extension of the current data model
(`ViewSecurityDefinition` already exposes everything needed) but was not
built out in this spike since it adds meaningful test surface for a
capability the scope only asked to be *assessed*, not delivered.

## Multiple predicate conditions

**Status: handled for AND-joined predicates.** `WHERE` clauses are split on
top-level `AND` into independent predicates, each independently classified
and translated (demonstrated by the combined CLS+RLS fixture view).
**Gap:** `OR`-joined predicates (e.g.
`WHERE is_account_group_member('a') OR is_account_group_member('b')`,
meaning "either group sees everything") are not decomposed — the whole `OR`
expression is currently handled as a single predicate node and will fall
into `GROUP_GATE` classification only if it's a bare function call (it
isn't, once wrapped in `OR`), so it will currently be classified
`UNSUPPORTED` and flagged for manual translation rather than mis-translated.
This is a reasonable next increment (split `OR` into a `group_predicates`
map the same way `AND`-split predicates are, but with an explicit "any of
these groups" semantic) but wasn't required to prove feasibility.

## Unsupported Fabric security scenarios

- **Per-user dynamic predicates (`USER_MATCH`)** — translated to a
  `USERPRINCIPALNAME()`-based predicate as a best guess, but flagged
  `requires_validation: true`. Whether Fabric's OneLake Data Access Roles
  row-filter grammar actually supports a "calling principal" function
  needs to be confirmed against a live tenant before this pattern is relied
  on (see Technical Assessment §4).
- **Column-level security beyond permit/mask-to-null/mask-to-literal** —
  Databricks UC also supports arbitrary masking functions (e.g.
  hash/tokenize a column rather than nulling it). The parser only recognizes
  the `CASE WHEN <membership> THEN col ELSE <literal-or-null> END` shape;
  a masking UDF call in the `ELSE` branch is captured as `else_value` text
  but not further interpreted — Fabric's column masking behavior would need
  to be manually matched to the specific UDF's semantics.
- **`SELECT *` views** — flagged and skipped for column-level extraction,
  since the concrete output column list isn't resolvable from the view DDL
  text alone (it depends on the base table's live schema). A production
  collector would resolve `SELECT *` via `DESCRIBE`/`INFORMATION_SCHEMA`
  before parsing.
- **Table-level grants (non-view-based UC permissions)** — this spike's
  scope was specifically view-embedded CLS/RLS; classic UC `GRANT SELECT ON
  TABLE ... TO group` statements (with no CLS/RLS logic) are a separate,
  simpler translation path (maps directly to a Fabric role with no column
  or row rules) that was not built out here but is a straightforward
  addition given the same role-building infrastructure.
- **Multi-table row filters** — see "Complex view definitions" above.

## Summary table

| Scenario | Extraction | Translation | Recommended production follow-up |
|---|---|---|---|
| Derived columns | Full | Full (per assumption) | Extend to detect masks embedded inside derived expressions |
| Simple CLS mask | Full | Full | — |
| Simple RLS group gate | Full | Full | — |
| RLS group→attribute (CASE) | Full | Full | — |
| RLS user-identity match | Full | Best-effort, flagged | Validate Fabric per-user predicate support |
| Nested views | Detected | Not composed | Add topological resolution pass |
| Complex views (join/agg/window/union) | Best-effort, flagged | Not attempted | Manual review per flagged view |
| `OR`-joined predicates | Captured as one node | Flagged `UNSUPPORTED` | Extend predicate splitter |
| `SELECT *` views | Flagged, skipped | N/A | Resolve schema out of band before parsing |
| Non-view UC table grants | Not in scope | N/A | Separate, simpler translation path |
