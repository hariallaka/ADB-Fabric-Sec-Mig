import os

import pytest

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")


@pytest.fixture(scope="module")
def views():
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    return {v.fq_name: v for v in parse_views_file(FIXTURE, grants_by_view=grants)}


def test_derived_column_assumption(views):
    """The spike's key design assumption: `c = a * b` must be flagged
    derived and excluded from the flattened column list; `a`/`b` (its
    source columns) must be included.
    """
    v = views["sec.finance.v_derived_example"]
    assert v.derived_output_columns == ["c"]
    assert v.select_columns == ["a", "b"]
    assert v.where_clause_sql is None


def test_grants_are_read_not_inferred_from_sql(views):
    """Access comes only from the grants file -- never from parsing the
    view's SQL text (e.g. no is_account_group_member()-style pattern is
    treated specially anywhere).
    """
    v = views["sec.finance.v_derived_example"]
    assert v.grantees == ["finance_readers"]

    v2 = views["sec.finance.v_my_expense_reports"]
    # WHERE clause carries a function call (current_user()); it must be
    # preserved verbatim and not parsed into a grant/permission.
    assert v2.where_clause_sql == "submitted_by = CURRENT_USER()"
    assert v2.grantees == ["finance_readers"]


def test_and_where_clause_preserved_verbatim(views):
    v = views["sec.hr.v_employee_basic"]
    assert v.where_clause_sql == "dept = 'Engineering' AND active = TRUE"
    assert v.select_columns == ["emp_id", "name", "dept"]


def test_or_where_clause_preserved_verbatim(views):
    """Edge case required by the spike: OR-joined WHERE predicates must
    survive translation unchanged, not be dropped or decomposed.
    """
    v = views["sec.sales.v_orders_by_region"]
    assert v.where_clause_sql == "region = 'US' OR region = 'CA'"
    assert v.grantees == ["sales_region_us", "sales_region_eu"]


def test_nested_and_or_where_clause_preserved(views):
    v = views["sec.sales.v_orders_secure"]
    assert v.where_clause_sql == "(region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH'"
    # unit_price/quantity are direct + derived-source columns (deduped);
    # total_amount (the derived alias) must not appear.
    assert v.select_columns == ["order_id", "customer", "unit_price", "quantity"]
    assert v.derived_output_columns == ["total_amount"]


def test_nested_view_flagged(views):
    v = views["sec.hr.v_employee_export"]
    assert v.references_views == ["v_employee_basic"]
    assert any("nested view" in msg for msg in v.unsupported_constructs)


def test_complex_view_flagged_but_still_flattened(views):
    v = views["sec.sales.v_regional_totals"]
    assert v.is_complex is True
    assert v.base_tables == ["sec.sales.orders", "sec.sales.regions"]
    assert any("JOIN" in msg for msg in v.unsupported_constructs)
    # SUM(o.amount) AS total_amount -> "amount" is a derived source column,
    # "total_amount" is excluded.
    assert v.select_columns == ["region", "amount"]
    assert v.derived_output_columns == ["total_amount"]


def test_reformatted_select_sql_matches_spike_example(views):
    """Mirrors the spike's own worked example: `select a,b,c,d*e as f from
    table1 where a=5 and c=6` -> `select a,b,c,d,e from table1 where a=5
    and c=6`.
    """
    v = views["sec.sales.v_orders_secure"]
    assert v.reformatted_select_sql == (
        "SELECT order_id, customer, unit_price, quantity FROM sec.sales.order_lines "
        "WHERE (region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH'"
    )
