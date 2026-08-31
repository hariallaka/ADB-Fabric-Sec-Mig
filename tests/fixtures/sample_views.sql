-- Fixture views used by the extraction/translation test suite and the POC
-- demo run. Access is driven entirely by tests/fixtures/grants_sample.csv
-- (who holds SELECT on each view) -- these view definitions only describe
-- *what data* a grant covers, never *who* gets it.

-- 1. Derived-column example straight from the ticket's key design
--    assumption: `c` is derived from `a` and `b` and must NOT receive a
--    direct CLS grant; `a` and `b` are the CLS-eligible flattened columns.
--    No WHERE clause -> unrestricted (TRUE) row filter.
CREATE OR REPLACE VIEW sec.finance.v_derived_example AS
SELECT
  a,
  b,
  a * b AS c
FROM sec.finance.table1;

-- 2. Plain view with an AND-joined WHERE clause, verified to be carried
--    through to the reformatted SELECT verbatim (no decomposition).
CREATE OR REPLACE VIEW sec.hr.v_employee_basic AS
SELECT emp_id, name, dept
FROM sec.hr.employee
WHERE dept = 'Engineering' AND active = true;

-- 3. OR-joined WHERE clause -- must survive translation unchanged, per the
--    requirement that OR edge cases in the WHERE clause are met.
CREATE OR REPLACE VIEW sec.sales.v_orders_by_region AS
SELECT order_id, customer, region, amount
FROM sec.sales.orders
WHERE region = 'US' OR region = 'CA';

-- 4. Combined derived column + a nested AND/OR WHERE clause, to exercise
--    both rules together on one view.
CREATE OR REPLACE VIEW sec.sales.v_orders_secure AS
SELECT
  order_id,
  customer,
  unit_price,
  quantity,
  unit_price * quantity AS total_amount
FROM sec.sales.order_lines
WHERE (region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH';

-- 5. Nested view: built on top of view #2 above. Flagged as a nested-view
--    dependency requiring composed translation (see limitations doc).
CREATE OR REPLACE VIEW sec.hr.v_employee_export AS
SELECT emp_id, name
FROM sec.hr.v_employee_basic
WHERE dept = 'Engineering';

-- 6. Complex view: JOIN + aggregation. Flagged for manual review; the
--    flattened column list and reformatted SELECT are still attempted on a
--    best-effort basis.
CREATE OR REPLACE VIEW sec.sales.v_regional_totals AS
SELECT
  o.region,
  SUM(o.amount) AS total_amount
FROM sec.sales.orders o
JOIN sec.sales.regions r ON o.region = r.region_code
WHERE o.active = true
GROUP BY o.region;

-- 7. Function call in the WHERE clause (not a group-membership check --
--    this toolkit no longer treats any WHERE-clause function specially; it
--    is carried through verbatim like any other predicate).
CREATE OR REPLACE VIEW sec.finance.v_my_expense_reports AS
SELECT report_id, submitted_by, amount
FROM sec.finance.expense_reports
WHERE submitted_by = current_user();

-- 8. Join with an UNQUALIFIED column reference -- the exact ambiguity
--    column-to-table attribution has to resolve correctly: `region_name`
--    lives only on `regions`, not `orders`, but is written bare (no `r.`
--    qualifier) in the SELECT list. Without a table-columns schema this
--    would previously be silently misattributed to the alphabetically
--    first base table (`sec.sales.orders`, wrong); with one supplied it
--    resolves to the correct table, and without one it's now explicitly
--    flagged rather than guessed at silently.
CREATE OR REPLACE VIEW sec.sales.v_orders_with_region_name AS
SELECT order_id, amount, region_name
FROM sec.sales.orders o
JOIN sec.sales.regions r ON o.region = r.region_code;
