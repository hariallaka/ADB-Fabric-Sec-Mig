-- Fixture views used by the extraction/translation test suite and the POC
-- demo run. These mirror the patterns described in the spike scope.

-- 1. Derived-column example straight from the ticket's key design
--    assumption: `c` is derived from `a` and `b` and must NOT receive a
--    direct CLS grant; `a` and `b` are the CLS-eligible source columns.
CREATE OR REPLACE VIEW sec.finance.v_derived_example AS
SELECT
  a,
  b,
  a * b AS c
FROM sec.finance.table1;

-- 2. Column-level security (CLS) via the Databricks dynamic-view masking
--    pattern: CASE WHEN is_account_group_member(...) THEN col ELSE ... END.
CREATE OR REPLACE VIEW sec.hr.v_employee_cls AS
SELECT
  emp_id,
  name,
  CASE WHEN is_account_group_member('finance_readers') THEN salary ELSE NULL END AS salary,
  CASE WHEN is_account_group_member('hr_full_access') THEN ssn ELSE 'REDACTED' END AS ssn
FROM sec.hr.employee;

-- 3. Row-level security (RLS): simple group gate. Every row is visible to
--    any member of `all_employees_view`; the filter carries no per-row
--    attribute, so it does not need row-level predicate translation in
--    Fabric, only role-membership scoping.
CREATE OR REPLACE VIEW sec.hr.v_employee_gated AS
SELECT emp_id, name, dept
FROM sec.hr.employee
WHERE is_account_group_member('all_employees_view');

-- 4. Row-level security (RLS): group-to-attribute predicate. Each AD group
--    maps to a distinct row predicate (region = 'US' / region = 'EU').
CREATE OR REPLACE VIEW sec.sales.v_orders_by_region AS
SELECT order_id, customer, region, amount
FROM sec.sales.orders
WHERE region = CASE
    WHEN is_account_group_member('sales_region_us') THEN 'US'
    WHEN is_account_group_member('sales_region_eu') THEN 'EU'
    WHEN is_account_group_member('sales_admin') THEN region
  END;

-- 5. Combined CLS + RLS + a derived column in the same view.
CREATE OR REPLACE VIEW sec.sales.v_orders_secure AS
SELECT
  order_id,
  customer,
  CASE WHEN is_account_group_member('sales_finance') THEN unit_price ELSE NULL END AS unit_price,
  quantity,
  unit_price * quantity AS total_amount
FROM sec.sales.order_lines
WHERE region = CASE
    WHEN is_account_group_member('sales_region_us') THEN 'US'
    WHEN is_account_group_member('sales_region_eu') THEN 'EU'
  END;

-- 6. Nested view: built on top of view #3 above. Should be flagged as a
--    nested-view dependency requiring composed translation.
CREATE OR REPLACE VIEW sec.hr.v_employee_gated_export AS
SELECT emp_id, name
FROM sec.hr.v_employee_gated
WHERE is_account_group_member('export_team');

-- 7. Complex view: JOIN + aggregation. Flagged for manual review; lineage
--    is still attempted on a best-effort basis.
CREATE OR REPLACE VIEW sec.sales.v_regional_totals AS
SELECT
  o.region,
  SUM(o.amount) AS total_amount
FROM sec.sales.orders o
JOIN sec.sales.regions r ON o.region = r.region_code
WHERE is_account_group_member('sales_admin')
GROUP BY o.region;

-- 8. User-identity row filter (ownership pattern), not a group-based RLS
--    construct -- flagged as USER_MATCH for a documented, separate
--    translation path (Fabric per-user predicate via USERPRINCIPALNAME()).
CREATE OR REPLACE VIEW sec.finance.v_my_expense_reports AS
SELECT report_id, submitted_by, amount
FROM sec.finance.expense_reports
WHERE submitted_by = current_user();
