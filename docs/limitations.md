# Limitation Analysis (AC5)

Validated against the scope's named scenarios plus additional gaps found
while building and testing the extraction/translation logic.

## Native Unity Catalog row filters / column masks (not covered)

**Status: out of scope for this toolkit — read this before relying on the
feasibility conclusion.** This toolkit's security model is entirely
view-based: a view's SELECT grantees plus its SELECT-list/WHERE-clause
shape. Since Unity Catalog's GA release, some estates instead (or
additionally) implement RLS/CLS **natively on tables**, independent of any
view:

```sql
ALTER TABLE sec.hr.employee SET ROW FILTER hr.filter_by_region ON (region);
ALTER TABLE sec.hr.employee ALTER COLUMN salary SET MASK hr.mask_salary;
```

These live in `information_schema.table_row_filters` /
`information_schema.column_masks`, not in a view's grants or SQL text at
all, and this toolkit does not read either. If a target table has a native
row filter or column mask *and* is also exposed through a view this toolkit
processes, the view-level translation this toolkit produces does not
account for that additional native restriction. **Before committing
production scope to this approach, run `SHOW ROW FILTERS`/`SHOW COLUMN
MASKS` against a representative sample of target catalogs** to confirm this
gap doesn't affect the tables in scope.

## Extraction identity must be able to see every grant, not just its own

**Status: understood and mitigated via a one-time bootstrap step, not a
code limitation.** `information_schema.table_privileges` only surfaces the
grants the querying identity is entitled to see: broadly, privileges it
holds or granted itself, or *every* privilege if it owns the object, holds
`MANAGE` on it, or is a metastore/account admin. An extraction identity
with only `SELECT` on a view will see that view's own definition but will
**silently** miss other principals' grants on it -- no error, just an
incomplete `extracted_grants.csv`. This toolkit ships a fix
(`dbx_fabric_security.cli grant-catalog-access`, run once by an existing
catalog owner/admin to make the extraction identity a catalog owner or
grant it `ALL PRIVILEGES`), but it's worth calling out explicitly here: a
pipeline running under an under-provisioned identity won't fail loudly, it
will just under-report access, which is a worse failure mode than an error.
Cross-check `extracted_grants.csv`'s row counts against expectations after
the first live run.

## Derived columns

**Status: handled per the spike's key design assumption, validated by
tests.** `a * b AS c` traces `c` back to its source columns `a`/`b` (via
sqlglot's expression tree); `c` never appears in the flattened
column list, so it never receives a CLS entitlement, while `a` and `b` do
(for every principal granted SELECT on the view).

**Gap:** if a derived expression's *own* source column is itself only
reachable through another view (a nested view — see below), the source
column resolves at the immediate view's level only; it is not traced
further back through the base view's definition.

## Complex view definitions (joins)

**Status: CLS column-to-table attribution is solved; RLS row-filter
attribution is not (and is architecturally harder).** Any view with a
`JOIN`, `GROUP BY`, window function, subquery, or `UNION` is still marked
`is_complex = true` and added to `unsupported_constructs`, but the two
things that flag covers are no longer the same risk:

- **CLS (which table a column belongs to):** solved. Each entry in
  `select_columns` is resolved to its real source table
  (`ViewDefinition.column_source_tables`), not blanket-attributed to
  `base_tables[0]`. A column the view's SQL qualifies (`t1.a`) resolves
  directly via the FROM/JOIN alias map. An unqualified column resolves
  deterministically once each candidate table's real column list is known
  (`DatabricksApiClient.fetch_table_columns` / `--table-columns`) — and
  that resolution is genuinely deterministic, not a best guess: Databricks/
  Spark SQL refuses to `CREATE VIEW` in the first place if an unqualified
  reference is ambiguous across the joined tables, so once the schemas are
  known there is at most one correct answer (barring a table's schema
  drifting *after* the view was created, which is still flagged, not
  guessed at — see below). Without a table-columns schema supplied, an
  unqualified column in a multi-table view still falls back to
  `base_tables[0]`, exactly as before this fix — but now says so
  explicitly per column in `unsupported_constructs`, rather than silently.
  A column present in more than one supplied table's schema (schema drift,
  not a compile-time-valid ambiguity) is likewise flagged, not guessed.
- **RLS (which table a WHERE-clause predicate belongs to):** still not
  attempted. A WHERE clause spanning columns from multiple joined tables
  has no single physical table to become a Fabric row filter against —
  Fabric's per-table row filter can't express a cross-table predicate
  without the join itself, so `rls_translator.py` still attributes the
  whole predicate to `base_tables[0]` unconditionally. This is a harder,
  architecturally distinct problem from column attribution (there's no
  equivalent "ask the table for its schema" fix — it would require
  decomposing the predicate by which table each referenced column
  actually belongs to, and deciding what a single-table row filter should
  even mean for a condition that inherently spans two tables). Output for
  a multi-table view's row filter should still be treated as a starting
  point for manual review, not an auto-deployable result.

## Nested views

**Status: detected, not resolved.** A view built on another view (e.g.
`v_employee_export` selecting from `v_employee_basic`) is flagged via
`references_views` / `unsupported_constructs`. The grants on the *base*
view are not automatically composed into the dependent view's translation —
i.e. `v_employee_export`'s own SELECT grantees are translated correctly,
but if the base view (`v_employee_basic`) also carries its own row filter,
that filter is not merged in. **Mitigation for production:** resolve nested
views in dependency order (topological sort over `references_views`),
composing a base view's WHERE clause as an additional `AND` predicate and
its flattened columns as an additional column-scope constraint on the
dependent view's translation, before role-building. This is a
straightforward extension of the current data model but was not built out
in this spike since it adds meaningful scope for a capability the ticket
only asked to be *assessed*, not delivered.

## Multiple predicate conditions (including OR)

**Status: fully handled — this was the main new requirement validated in
this pass.** The WHERE clause is never decomposed; it is captured and
reproduced **verbatim**, structure and all. This means `AND`, `OR`, `NOT`,
and arbitrary nesting (`(a AND b) OR c`) all round-trip unchanged by
construction — there is no special-case logic for OR because there is no
decomposition logic at all to trip over it. Validated directly by
`tests/test_view_parser.py::test_or_where_clause_preserved_verbatim`,
`test_nested_and_or_where_clause_preserved`, and the matching RLS
translator tests. This is a simpler and more robust position than the
previous design (which tried to classify and split predicates by identity
function) — see `docs/technical-assessment.md` §1 for why that approach was
dropped.

## Unsupported Fabric security scenarios

- **Fabric's row-filter grammar vs. arbitrary Databricks SQL predicates** —
  the WHERE clause is reproduced verbatim in Databricks SQL syntax; Fabric's
  actual row-filter expression grammar (once its schema is confirmed, per
  the Technical Assessment §4) may not accept every SQL construct
  Databricks does (certain functions, date arithmetic, etc.). This is a
  translation-target risk, not an extraction gap — flagged for validation
  once the Fabric API schema is confirmed.
- **`SELECT *` views** — flagged and skipped for column-level extraction,
  since the concrete output column list isn't resolvable from the view DDL
  text alone (it depends on the base table's live schema). A production
  collector would resolve `SELECT *` via `DESCRIBE`/`INFORMATION_SCHEMA`
  before parsing.
- **Individual-user grants** — Unity Catalog allows granting SELECT
  directly to a user, not just a group. This toolkit treats every principal
  uniformly and does attempt to resolve a user's object id via SCIM (see
  `DatabricksApiClient.fetch_principal_object_id`, which checks Groups then
  Users) the same way it resolves a group's; if that lookup can't find a
  match (or the extraction identity lacks SCIM read access), the grant
  comes back `unresolvedPrincipalObjectId: true` and is flagged for manual
  resolution rather than silently dropped or deployed with a guessed id.
- **Table-level grants (no view involved)** — this spike's scope was
  specifically Unity Catalog views; classic `GRANT SELECT ON TABLE ... TO
  group` statements with no view in between are a separate, simpler
  translation path (maps directly to a Fabric role with no column
  filtering) that was not built out here but is a straightforward addition
  given the same role-building infrastructure.
- **Multi-table (joined) views** — see "Complex view definitions" above.

## Summary table

| Scenario | Extraction | Translation | Recommended production follow-up |
|---|---|---|---|
| Native UC row filters / column masks (`ALTER TABLE ... SET ROW FILTER/MASK`) | **Not covered** | N/A | Confirm the real estate's tables don't rely on these before finalizing scope |
| Extraction identity under-provisioned (only SELECT, not ownership/MANAGE/admin) | Silently incomplete grant list | N/A | Run `grant-catalog-access` once per catalog before first use; cross-check row counts |
| Derived columns | Full | Full (per assumption) | Extend to trace through nested views |
| Simple SELECT-grant CLS | Full | Full | — |
| WHERE clause with AND | Full (verbatim) | Full (verbatim) | — |
| WHERE clause with OR / nested AND-OR | Full (verbatim) | Full (verbatim) | — |
| Nested views | Detected | Grants/filters not composed | Add topological resolution pass |
| Complex views: CLS column-to-table attribution | Full, given `table_columns`; flagged fallback without it | Full -- each column's real table, not a blanket guess | Supply `table_columns`/`--table-columns` (or `fetch_table_columns` live) for every join |
| Complex views: RLS row-filter table attribution | Not attempted | Keyed to first base table unconditionally | Manual review per flagged multi-table view |
| `SELECT *` views | Flagged, skipped | N/A | Resolve schema out of band before parsing |
| Individual-user grants | Full | Full, flagged unresolved if SCIM can't match | Decide production posture for non-group grants |
| Non-view UC table grants | Not in scope | N/A | Separate, simpler translation path |
