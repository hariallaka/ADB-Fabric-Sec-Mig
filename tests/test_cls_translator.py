import json
import os

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.translator.cls_translator import translate_cls

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")
TABLE_COLUMNS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "table_columns_sample.json")


def _views(table_columns=None):
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    return parse_views_file(FIXTURE, grants_by_view=grants, table_columns=table_columns)


def test_derived_column_never_gets_direct_entitlement():
    views = [v for v in _views() if v.fq_name == "sec.finance.v_derived_example"]
    entitlements = translate_cls(views)

    columns = {e.column for e in entitlements}
    assert columns == {"a", "b"}
    assert "c" not in columns
    assert all(e.principal == "finance_readers" for e in entitlements)
    assert all(e.table == "sec.finance.table1" for e in entitlements)


def test_every_grantee_gets_every_flattened_column():
    views = [v for v in _views() if v.fq_name == "sec.sales.v_orders_by_region"]
    entitlements = translate_cls(views)

    by_principal: dict[str, set[str]] = {}
    for e in entitlements:
        by_principal.setdefault(e.principal, set()).add(e.column)

    assert by_principal["sales_region_us"] == {"order_id", "customer", "region", "amount"}
    assert by_principal["sales_region_eu"] == {"order_id", "customer", "region", "amount"}


def test_view_with_no_grantees_produces_no_entitlements():
    views = _views()
    for v in views:
        v.grantees = []
    assert translate_cls(views) == []


def test_join_column_attributed_to_its_real_table_when_schema_supplied():
    """The scenario the fix addresses, end to end: `region_name` in a join
    must get a CLS entitlement against `sec.sales.regions`, not
    `sec.sales.orders`, once table schemas are supplied.
    """
    with open(TABLE_COLUMNS_FIXTURE, encoding="utf-8") as fh:
        table_columns = json.load(fh)
    views = [v for v in _views(table_columns) if v.fq_name == "sec.sales.v_orders_with_region_name"]
    entitlements = translate_cls(views)

    by_column = {e.column: e.table for e in entitlements}
    assert by_column["order_id"] == "sec.sales.orders"
    assert by_column["amount"] == "sec.sales.orders"
    assert by_column["region_name"] == "sec.sales.regions"


def test_join_column_falls_back_with_no_schema_supplied():
    """Without table_columns, the same view's entitlements still get
    produced (not silently dropped) but region_name is attributed to the
    fallback table -- this is the pre-fix behavior, now an explicit,
    documented fallback rather than a silent one.
    """
    views = [v for v in _views() if v.fq_name == "sec.sales.v_orders_with_region_name"]
    entitlements = translate_cls(views)

    by_column = {e.column: e.table for e in entitlements}
    assert by_column["region_name"] == "sec.sales.orders"  # wrong table, but consistent w/ the flag
