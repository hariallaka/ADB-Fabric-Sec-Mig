# Proof-of-Concept Findings

All findings below are reproducible by running:

```bash
pip install -e .
python -m dbx_fabric_security.cli run-all \
  --views tests/fixtures/sample_views.sql \
  --ags-export tests/fixtures/ags_export_sample.csv \
  --targets tests/fixtures/deploy_targets_sample.json \
  --out-dir out/demo
pytest tests/ -v
```

## Test suite: 19/19 passing

```
tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement PASSED
tests/test_cls_translator.py::test_masked_columns_produce_permit_entitlements PASSED
tests/test_cls_translator.py::test_plain_columns_are_default_visible PASSED
tests/test_deploy.py::test_dry_run_never_calls_network_and_reports_plan PASSED
tests/test_deploy.py::test_tables_without_target_mapping_are_skipped PASSED
tests/test_rls_translator.py::test_group_gate_translates_to_true_predicate_per_group PASSED
tests/test_rls_translator.py::test_group_attribute_predicate_split_per_group PASSED
tests/test_rls_translator.py::test_user_match_rewritten_and_flagged_for_validation PASSED
tests/test_role_builder_and_mapping.py::test_role_builder_merges_cls_and_rls_per_table_and_group PASSED
tests/test_role_builder_and_mapping.py::test_role_builder_flags_unresolved_group PASSED
tests/test_role_builder_and_mapping.py::test_role_mapping_ties_ags_to_fabric_role PASSED
tests/test_view_parser.py::test_derived_column_assumption PASSED
tests/test_view_parser.py::test_cls_mask_extraction PASSED
tests/test_view_parser.py::test_group_gate_row_filter PASSED
tests/test_view_parser.py::test_group_attribute_row_filter PASSED
tests/test_view_parser.py::test_combined_cls_and_rls_view PASSED
tests/test_view_parser.py::test_nested_view_flagged PASSED
tests/test_view_parser.py::test_complex_view_flagged PASSED
tests/test_view_parser.py::test_user_match_row_filter PASSED

19 passed in 0.26s
```

## AC1 — CLS feasibility: evidence

Input (`tests/fixtures/sample_views.sql`, view 2):

```sql
CREATE OR REPLACE VIEW sec.hr.v_employee_cls AS
SELECT
  emp_id,
  name,
  CASE WHEN is_account_group_member('finance_readers') THEN salary ELSE NULL END AS salary,
  CASE WHEN is_account_group_member('hr_full_access') THEN ssn ELSE 'REDACTED' END AS ssn
FROM sec.hr.employee;
```

Extracted + translated output (`out/demo/cls_entitlements.json`, filtered):

```json
[
  {"view": "sec.hr.v_employee_cls", "table": "sec.hr.employee", "column": "salary",
   "adGroup": "finance_readers", "accessEffect": "PERMIT", "sourceType": "MASKED",
   "maskElseValue": "NULL"},
  {"view": "sec.hr.v_employee_cls", "table": "sec.hr.employee", "column": "ssn",
   "adGroup": "hr_full_access", "accessEffect": "PERMIT", "sourceType": "MASKED",
   "maskElseValue": "'REDACTED'"},
  {"view": "sec.hr.v_employee_cls", "table": "sec.hr.employee", "column": "emp_id",
   "adGroup": null, "accessEffect": "DEFAULT_VISIBLE", "sourceType": "DIRECT"}
]
```

**Key design assumption validated** — derived-column example
(`tests/fixtures/sample_views.sql`, view 1):

```sql
CREATE OR REPLACE VIEW sec.finance.v_derived_example AS
SELECT a, b, a * b AS c FROM sec.finance.table1;
```

Result: `derived_columns == ["c"]`; CLS entitlements generated for `a` and
`b` (tagged `DERIVED_SOURCE`, `derivedOutputColumn: "c"`); **zero**
entitlements generated for `c`. Enforced by
`tests/test_view_parser.py::test_derived_column_assumption` and
`tests/test_cls_translator.py::test_derived_column_never_gets_direct_entitlement`.

**Structured export (AC1 requirement):** both JSON (`cls_entitlements.json`)
and CSV (`cls_entitlements.csv`) are produced by
`dbx_fabric_security.cli translate`.

## AC2 — RLS feasibility: evidence

Input (`tests/fixtures/sample_views.sql`, view 4):

```sql
CREATE OR REPLACE VIEW sec.sales.v_orders_by_region AS
SELECT order_id, customer, region, amount
FROM sec.sales.orders
WHERE region = CASE
    WHEN is_account_group_member('sales_region_us') THEN 'US'
    WHEN is_account_group_member('sales_region_eu') THEN 'EU'
    WHEN is_account_group_member('sales_admin') THEN region
  END;
```

Extracted + translated output (`out/demo/rls_entitlements.json`, filtered):

```json
[
  {"view": "sec.sales.v_orders_by_region", "table": "sec.sales.orders",
   "adGroup": "sales_region_us", "rowFilterPredicate": "region = 'US'",
   "filterType": "GROUP_ATTRIBUTE"},
  {"view": "sec.sales.v_orders_by_region", "table": "sec.sales.orders",
   "adGroup": "sales_region_eu", "rowFilterPredicate": "region = 'EU'",
   "filterType": "GROUP_ATTRIBUTE"},
  {"view": "sec.sales.v_orders_by_region", "table": "sec.sales.orders",
   "adGroup": "sales_admin", "rowFilterPredicate": "TRUE",
   "filterType": "GROUP_ATTRIBUTE"}
]
```

Note the `sales_admin` branch (`THEN region`, i.e. "no restriction") was
correctly normalized from the literal `region = region` to `TRUE`.

## AC3/AC4 — Fabric role generation + automated deployment feasibility

Merged Fabric Data Access Role payload for `sec.hr.employee` /
`finance_readers` (`out/demo/fabric_data_access_roles.json`, one entry):

```json
{
  "name": "role_sec_hr_employee_finance_readers",
  "table": "sec.hr.employee",
  "members": {
    "microsoftEntraMembers": [
      {"objectId": "7c3a4e10-1111-4a2b-9c1d-000000000001",
       "objectType": "Group", "groupName": "finance_readers"}
    ]
  },
  "decisionRules": [
    {"effect": "Permit",
     "permission": [{"attributeName": "Path", "attributeValueIncludedIn": ["Tables/employee"]}]}
  ],
  "columnRules": {"permit": ["salary"], "note": "..."},
  "rowFilters": ["TRUE"],
  "unresolvedAdGroupObjectId": false
}
```

AGS → AD Group → Fabric Role mapping (`out/demo/ags_role_mapping.csv`,
10 rows generated from 8 fixture views; excerpt below):

```
agsId,agsName,adGroupName,fabricRoleName,oneLakeObject,columnPermitCount,rowFilters
AGS-1003,All Employees View,all_employees_view,role_sec_hr_employee_all_employees_view,sec.hr.employee,0,["TRUE"]
AGS-1001,Finance Data Readers,finance_readers,role_sec_hr_employee_finance_readers,sec.hr.employee,1,["TRUE"]
AGS-1002,HR Full Access,hr_full_access,role_sec_hr_employee_hr_full_access,sec.hr.employee,1,["TRUE"]
AGS-1007,Sales Finance,sales_finance,role_sec_sales_order_lines_sales_finance,sec.sales.order_lines,1,["TRUE"]
AGS-1005,Sales Region EU,sales_region_eu,role_sec_sales_order_lines_sales_region_eu,sec.sales.order_lines,0,["region = 'EU'"]
AGS-1004,Sales Region US,sales_region_us,role_sec_sales_order_lines_sales_region_us,sec.sales.order_lines,0,["region = 'US'"]
AGS-1006,Sales Admin,sales_admin,role_sec_sales_orders_sales_admin,sec.sales.orders,0,["TRUE"]
```

**Automated deployment feasibility:** `cli deploy` (dry-run by default)
produced a deployment plan/report for 3 target Lakehouse items without any
live network call:

```
Deployment (DRY-RUN): 3 item(s) targeted -> out/demo/deployment_report.json
  Skipped (no target mapping configured): ['sec.hr.v_employee_gated']
```

The one skipped table is `sec.hr.v_employee_gated`, a **view**, not a
physical table — correctly excluded since it isn't a deployable Fabric
target; it's a dependency of the nested view `v_employee_gated_export`,
consistent with the nested-view limitation documented separately.

## AC5 — Limitation coverage: evidence

Out of the 8 fixture views, extraction correctly flagged the 2 views that
should require manual review:

```
Extracted 8 view(s) -> out/demo/view_security_definitions.json
  2 view(s) flagged for manual review:
    ['sec.hr.v_employee_gated_export', 'sec.sales.v_regional_totals']
```

- `v_employee_gated_export` — nested view (built on `v_employee_gated`).
- `v_regional_totals` — complex view (JOIN + GROUP BY).

Both were still parsed on a best-effort basis (row filter and lineage were
extracted for `v_regional_totals` despite the join), but are marked
`unsupported_constructs`-non-empty so an automation pipeline can gate
deployment on manual sign-off for exactly these views, per
[limitations.md](./limitations.md).

## Summary

| Deliverable evidence requested | Found in |
|---|---|
| CLS extraction feasibility | §AC1 above, `tests/test_view_parser.py`, `tests/test_cls_translator.py` |
| RLS extraction feasibility | §AC2 above, `tests/test_view_parser.py`, `tests/test_rls_translator.py` |
| Fabric role creation feasibility | §AC3/AC4 above, `tests/test_role_builder_and_mapping.py` |
| Automated deployment feasibility | §AC3/AC4 above, `tests/test_deploy.py`, `fabric_api/deploy.py` |
