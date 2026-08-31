# Proof-of-Concept Findings

All findings below are reproducible by running:

```bash
pip install -e .
python -m dbx_fabric_security.cli run-all \
  --views tests/fixtures/sample_views.sql \
  --grants tests/fixtures/grants_sample.csv \
  --targets tests/fixtures/deploy_targets_sample.json \
  --out-dir out/demo
pytest tests/ -v
```

## Test suite: 37/37 passing

```
tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement PASSED
tests/test_cls_translator.py::test_every_grantee_gets_every_flattened_column PASSED
tests/test_cls_translator.py::test_view_with_no_grantees_produces_no_entitlements PASSED
tests/test_databricks_client.py::test_dry_run_never_calls_network_and_returns_empty PASSED
tests/test_databricks_client.py::test_fetch_view_ddl_dry_run_returns_empty_mapping PASSED
tests/test_databricks_client.py::test_fetch_view_grants_dry_run_returns_empty_mapping PASSED
tests/test_databricks_client.py::test_grants_reconstruction_shape PASSED
tests/test_databricks_client.py::test_fetch_principal_object_id_dry_run_returns_unknown PASSED
tests/test_databricks_client.py::test_fetch_principal_directory_dry_run_returns_empty PASSED
tests/test_databricks_client.py::test_fetch_principal_object_id_resolves_group_before_user PASSED
tests/test_databricks_client.py::test_fetch_principal_object_id_falls_back_to_user PASSED
tests/test_databricks_client.py::test_fetch_principal_directory_dedupes_and_skips_unresolved PASSED
tests/test_databricks_client.py::test_grant_catalog_access_owner_mode_dry_run PASSED
tests/test_databricks_client.py::test_grant_catalog_access_all_privileges_mode_dry_run PASSED
tests/test_databricks_client.py::test_grant_catalog_access_rejects_bad_mode PASSED
tests/test_databricks_client.py::test_missing_token_raises_on_live_call PASSED
tests/test_databricks_client.py::test_ddl_reconstruction_shape PASSED
tests/test_deploy.py::test_dry_run_never_calls_network_and_reports_plan PASSED
tests/test_deploy.py::test_tables_without_target_mapping_are_skipped PASSED
tests/test_rls_translator.py::test_no_where_clause_yields_unrestricted_filter PASSED
tests/test_rls_translator.py::test_and_predicate_carried_through_verbatim PASSED
tests/test_rls_translator.py::test_or_predicate_carried_through_verbatim_for_every_grantee PASSED
tests/test_rls_translator.py::test_nested_and_or_predicate_carried_through_verbatim PASSED
tests/test_rls_translator.py::test_view_with_no_grantees_produces_no_entitlements PASSED
tests/test_role_builder_and_mapping.py::test_role_builder_merges_cls_and_rls_per_table_and_principal PASSED
tests/test_role_builder_and_mapping.py::test_or_predicate_role_carries_full_predicate PASSED
tests/test_role_builder_and_mapping.py::test_role_builder_flags_unresolved_principal PASSED
tests/test_role_builder_and_mapping.py::test_grants_csv_principal_without_object_id_is_unresolved PASSED
tests/test_role_builder_and_mapping.py::test_role_mapping_flattens_roles_with_no_ags_involved PASSED
tests/test_view_parser.py::test_derived_column_assumption PASSED
tests/test_view_parser.py::test_grants_are_read_not_inferred_from_sql PASSED
tests/test_view_parser.py::test_and_where_clause_preserved_verbatim PASSED
tests/test_view_parser.py::test_or_where_clause_preserved_verbatim PASSED
tests/test_view_parser.py::test_nested_and_or_where_clause_preserved PASSED
tests/test_view_parser.py::test_nested_view_flagged PASSED
tests/test_view_parser.py::test_complex_view_flagged_but_still_flattened PASSED
tests/test_view_parser.py::test_reformatted_select_sql_matches_spike_example PASSED

37 passed in 0.40s
```

## AC1 — CLS feasibility: evidence

**Key design assumption validated** — derived-column example
(`tests/fixtures/sample_views.sql`, view 1):

```sql
CREATE OR REPLACE VIEW sec.finance.v_derived_example AS
SELECT a, b, a * b AS c FROM sec.finance.table1;
```

`grants_sample.csv` grants `finance_readers` SELECT on this view, with
object id `7c3a4e10-1111-4a2b-9c1d-000000000001`. Result:
`select_columns == ["a", "b"]`, `derived_output_columns == ["c"]`; CLS
entitlements generated for `a` and `b`; **zero** entitlements generated for
`c`. Enforced by `tests/test_view_parser.py::test_derived_column_assumption`
and `tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement`.

Extracted + translated output (`out/demo/cls_entitlements.json`, filtered):

```json
[
  {"view": "sec.finance.v_derived_example", "table": "sec.finance.table1",
   "column": "a", "principal": "finance_readers"},
  {"view": "sec.finance.v_derived_example", "table": "sec.finance.table1",
   "column": "b", "principal": "finance_readers"}
]
```

**Access comes from the grant, not the SQL** — `sec.finance.table1` has no
identity-check logic in its SQL at all; the entitlement exists purely
because `grants_sample.csv` records `finance_readers` holding `SELECT` on
the view. **Structured export (AC1 requirement):** both JSON
(`cls_entitlements.json`) and CSV (`cls_entitlements.csv`) are produced by
`dbx_fabric_security.cli translate`.

## AC2 — RLS feasibility: evidence, including the OR edge case

Input (`tests/fixtures/sample_views.sql`, view 4) — a derived column
**and** a nested `AND`/`OR` WHERE clause in the same view:

```sql
CREATE OR REPLACE VIEW sec.sales.v_orders_secure AS
SELECT
  order_id, customer, unit_price, quantity,
  unit_price * quantity AS total_amount
FROM sec.sales.order_lines
WHERE (region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH';
```

Reformatted SELECT produced by the toolkit (matches the spike's own worked
example: `select a,b,c,d*e as f ... where a=5 and c=6` → `select
a,b,c,d,e ... where a=5 and c=6`):

```sql
SELECT order_id, customer, unit_price, quantity FROM sec.sales.order_lines
WHERE (region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH'
```

The WHERE clause — including the `OR` and the nested `AND` — is reproduced
**character-for-character**, not decomposed or reinterpreted. A second,
simpler OR case (`tests/fixtures/sample_views.sql`, view 3):

```sql
CREATE OR REPLACE VIEW sec.sales.v_orders_by_region AS
SELECT order_id, customer, region, amount
FROM sec.sales.orders
WHERE region = 'US' OR region = 'CA';
```

RLS output (`out/demo/rls_entitlements.json`, filtered) for both of that
view's grantees:

```json
[
  {"view": "sec.sales.v_orders_by_region", "table": "sec.sales.orders",
   "principal": "sales_region_us", "rowFilterPredicate": "region = 'US' OR region = 'CA'"},
  {"view": "sec.sales.v_orders_by_region", "table": "sec.sales.orders",
   "principal": "sales_region_eu", "rowFilterPredicate": "region = 'US' OR region = 'CA'"}
]
```

Enforced by `tests/test_view_parser.py::test_or_where_clause_preserved_verbatim`,
`test_nested_and_or_where_clause_preserved`, and
`tests/test_rls_translator.py::test_or_predicate_carried_through_verbatim_for_every_grantee`.

## AC3/AC4 — Fabric role generation, principal object ids, and automated deployment feasibility

Merged Fabric Data Access Role payload for `sec.finance.table1` /
`finance_readers` (`out/demo/fabric_data_access_roles.json`, one entry) —
note the object id came from `grants_sample.csv`'s `principal_object_id`
column, the same field `extract-databricks` populates via a live SCIM
lookup; no AGS or other external identity export is involved anywhere in
this pipeline:

```json
{
  "name": "role_sec_finance_table1_finance_readers",
  "table": "sec.finance.table1",
  "members": {
    "microsoftEntraMembers": [
      {"objectId": "7c3a4e10-1111-4a2b-9c1d-000000000001",
       "objectType": "Group", "principalName": "finance_readers"}
    ]
  },
  "decisionRules": [
    {"effect": "Permit",
     "permission": [{"attributeName": "Path", "attributeValueIncludedIn": ["Tables/table1"]}]}
  ],
  "columnRules": {"permit": ["a", "b"]},
  "rowFilters": ["TRUE"],
  "unresolvedPrincipalObjectId": false
}
```

**Unresolved-principal handling, also demonstrated:** the fixture grants
`hr_contractor` SELECT on `sec.hr.v_employee_basic` with a deliberately
blank `principal_object_id`. The resulting role comes back
`unresolvedPrincipalObjectId: true`, flagged rather than silently deployed
or dropped:

```
Role mapping rows: 9 -> out/demo/role_mapping.csv
  WARNING: 1 principal(s) have no known object id (not in --grants'
  principal_object_id column): ['hr_contractor']
```

AD Group/principal → Fabric Role mapping (`out/demo/role_mapping.csv`, 9
rows generated from 7 fixture views; excerpt below):

```
principalName,principalObjectId,fabricRoleName,oneLakeObject,columnPermitCount,rowFilters
finance_readers,7c3a4e10-1111-...-000000000001,role_sec_finance_table1_finance_readers,sec.finance.table1,2,["TRUE"]
sales_region_us,7c3a4e10-3333-...-000000000003,role_sec_sales_orders_sales_region_us,sec.sales.orders,4,["region = 'US' OR region = 'CA'"]
hr_contractor,,role_sec_hr_employee_hr_contractor,sec.hr.employee,3,["dept = 'Engineering' AND active = TRUE"]
```

**Automated deployment feasibility:** `cli deploy` (dry-run by default)
produced a deployment plan/report for 5 target Lakehouse items without any
live network call:

```
Deployment (DRY-RUN): 5 item(s) targeted -> out/demo/deployment_report.json
  Skipped (no target mapping configured): ['sec.hr.v_employee_basic']
```

The one skipped table is `sec.hr.v_employee_basic`, a **view**, not a
physical table — the nested view `v_employee_export` selects from it, so a
role gets generated against that name, but it correctly has no deployment
target configured since it isn't a Fabric Lakehouse table (consistent with
the nested-view limitation documented separately).

## AC5 — Limitation coverage: evidence

Out of the 7 fixture views, extraction correctly flagged the 2 views that
should require manual review:

```
Extracted 7 view(s) -> out/demo/view_security_definitions.json
  2 view(s) flagged for manual review:
    ['sec.hr.v_employee_export', 'sec.sales.v_regional_totals']
```

- `v_employee_export` — nested view (built on `v_employee_basic`).
- `v_regional_totals` — complex view (JOIN + GROUP BY); still correctly
  flattened `region` and `amount` (from `SUM(o.amount)`) as CLS-eligible
  columns, excluding the derived alias `total_amount`.

Both were still parsed on a best-effort basis, but are marked
`unsupported_constructs`-non-empty so an automation pipeline can gate
deployment on manual sign-off for exactly these views, per
[limitations.md](./limitations.md).

## Summary

| Deliverable evidence requested | Found in |
|---|---|
| CLS extraction feasibility | §AC1 above, `tests/test_view_parser.py`, `tests/test_cls_translator.py` |
| RLS extraction feasibility, including OR edge cases | §AC2 above, `tests/test_view_parser.py`, `tests/test_rls_translator.py` |
| Fabric role creation + principal object id resolution feasibility | §AC3/AC4 above, `tests/test_role_builder_and_mapping.py`, `tests/test_databricks_client.py` |
| Automated deployment feasibility | §AC3/AC4 above, `tests/test_deploy.py`, `fabric_api/deploy.py` |
