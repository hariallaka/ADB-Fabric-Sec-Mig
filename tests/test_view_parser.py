import json
import os

import pytest

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")
TABLE_COLUMNS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "table_columns_sample.json")


@pytest.fixture(scope="module")
def views():
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    return {v.fq_name: v for v in parse_views_file(FIXTURE, grants_by_view=grants)}


@pytest.fixture(scope="module")
def views_with_table_columns():
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    with open(TABLE_COLUMNS_FIXTURE, encoding="utf-8") as fh:
        table_columns = json.load(fh)
    return {
        v.fq_name: v
        for v in parse_views_file(FIXTURE, grants_by_view=grants, table_columns=table_columns)
    }


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


def test_qualified_columns_in_join_resolve_correctly_without_table_columns(views):
    """A column the SQL itself qualifies (`o.region`, `o.amount`) never
    needs schema info to resolve -- the FROM/JOIN alias map is enough.
    """
    v = views["sec.sales.v_regional_totals"]
    assert v.column_source_tables == {
        "region": "sec.sales.orders",
        "amount": "sec.sales.orders",
    }
    # No column-attribution-specific warning; only the generic
    # JOIN/GROUP BY complexity note.
    assert not any(msg.startswith("Column '") for msg in v.unsupported_constructs)


def test_unqualified_join_column_misattribution_is_flagged_without_schema(views):
    """The exact scenario this fix addresses: `region_name` is unqualified
    and actually lives on `regions`, not `orders`. Without a table-columns
    schema, it falls back to the alphabetically-first base table (wrong)
    but must say so explicitly rather than resolving silently.
    """
    v = views["sec.sales.v_orders_with_region_name"]
    assert v.base_tables == ["sec.sales.orders", "sec.sales.regions"]
    # Wrong, but flagged -- this is the pre-fix behavior, now made explicit.
    assert v.column_source_tables["region_name"] == "sec.sales.orders"
    assert any(
        "region_name" in msg and "unqualified" in msg for msg in v.unsupported_constructs
    )


def test_unqualified_join_column_resolves_correctly_with_table_columns(views_with_table_columns):
    """With each base table's real column list supplied, the same
    unqualified `region_name` resolves to its actual table (`regions`),
    and the misattribution warning disappears.
    """
    v = views_with_table_columns["sec.sales.v_orders_with_region_name"]
    assert v.column_source_tables == {
        "order_id": "sec.sales.orders",
        "amount": "sec.sales.orders",
        "region_name": "sec.sales.regions",
    }
    assert not any(msg.startswith("Column '") for msg in v.unsupported_constructs)


def test_ambiguous_column_present_in_two_tables_is_flagged_not_guessed():
    """If a column name genuinely exists in more than one base table's
    supplied schema, it must be flagged rather than silently attributed to
    either one.
    """
    from dbx_fabric_security.extractor.view_parser import parse_view

    sql = """
    CREATE OR REPLACE VIEW sec.sales.v_ambiguous AS
    SELECT status
    FROM sec.sales.orders o
    JOIN sec.sales.order_lines ol ON o.order_id = ol.order_id
    """
    table_columns = {
        "sec.sales.orders": ["order_id", "status"],
        "sec.sales.order_lines": ["order_id", "status"],
    }
    v = parse_view(sql, table_columns=table_columns)
    assert any(
        "status" in msg and "ambiguous" in msg for msg in v.unsupported_constructs
    )
    # Still gets a (flagged, unverified) fallback rather than being dropped.
    assert v.column_source_tables["status"] == v.base_tables[0]
