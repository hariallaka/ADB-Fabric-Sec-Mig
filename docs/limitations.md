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

## Complex view definitions

**Status: detected and flagged, not blindly translated.** Any view with a
`JOIN`, `GROUP BY`, window function, subquery, or `UNION` is marked
`is_complex = true` and added to `unsupported_constructs`; the flattened
column list and WHERE clause are still extracted on a best-effort basis
(and were shown to work correctly for a straightforward join+aggregate
example in the PoC — see `sec.sales.v_regional_totals`), but output for
such views should be treated as a starting point for manual review, not an
auto-deployable result. **Rationale for not attempting full correctness:**
once multiple tables are joined, `base_tables` returns more than one table
and the toolkit's `(table, principal)` role model has no way to decide
which table a merged column or predicate really belongs to (`role_builder`
currently keys off `base_tables[0]`, i.e. the first table encountered) —
this needs a case-by-case decision by a data engineer reviewing the flagged
view, not a fully automated rule.

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
  uniformly; a user-level grant produces a Fabric role scoped to that one
  user, and — since only groups are tracked in the AGS export — comes back
  `unresolvedPrincipalObjectId: true` and is flagged for manual resolution
  rather than silently dropped or silently deployed with a guessed group.
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
| Derived columns | Full | Full (per assumption) | Extend to trace through nested views |
| Simple SELECT-grant CLS | Full | Full | — |
| WHERE clause with AND | Full (verbatim) | Full (verbatim) | — |
| WHERE clause with OR / nested AND-OR | Full (verbatim) | Full (verbatim) | — |
| Nested views | Detected | Grants/filters not composed | Add topological resolution pass |
| Complex views (join/agg/window/union) | Best-effort, flagged | Best-effort, keyed to first base table | Manual review per flagged view |
| `SELECT *` views | Flagged, skipped | N/A | Resolve schema out of band before parsing |
| Individual-user grants | Full | Full, flagged unresolved if not in AGS | Decide production posture for non-group grants |
| Non-view UC table grants | Not in scope | N/A | Separate, simpler translation path |
