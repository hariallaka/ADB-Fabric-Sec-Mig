import os

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.translator.cls_translator import translate_cls

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")


def _views():
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    return parse_views_file(FIXTURE, grants_by_view=grants)


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
