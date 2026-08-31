import os

from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.translator.rls_translator import translate_rls

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")


def _view(views, name):
    return [v for v in views if v.fq_name == name][0]


def test_group_gate_translates_to_true_predicate_per_group():
    views = parse_views_file(FIXTURE)
    v = _view(views, "sec.hr.v_employee_gated")
    entitlements = translate_rls([v])

    assert len(entitlements) == 1
    e = entitlements[0]
    assert e.ad_group == "all_employees_view"
    assert e.row_filter_predicate == "TRUE"
    assert e.filter_type == "GROUP_GATE"
    assert e.requires_validation is False


def test_group_attribute_predicate_split_per_group():
    views = parse_views_file(FIXTURE)
    v = _view(views, "sec.sales.v_orders_by_region")
    entitlements = translate_rls([v])

    by_group = {e.ad_group: e.row_filter_predicate for e in entitlements}
    assert by_group["sales_region_us"] == "region = 'US'"
    assert by_group["sales_region_eu"] == "region = 'EU'"
    # `region = region` (admin "no restriction" branch) normalizes to TRUE
    assert by_group["sales_admin"] == "TRUE"


def test_user_match_rewritten_and_flagged_for_validation():
    views = parse_views_file(FIXTURE)
    v = _view(views, "sec.finance.v_my_expense_reports")
    entitlements = translate_rls([v])

    assert len(entitlements) == 1
    e = entitlements[0]
    assert e.filter_type == "USER_MATCH"
    assert e.requires_validation is True
    assert "USERPRINCIPALNAME()" in e.row_filter_predicate
    assert e.ad_group is None
