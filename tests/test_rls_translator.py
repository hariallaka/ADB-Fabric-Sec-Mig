import os

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.translator.rls_translator import translate_rls

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")


def _view(name):
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    views = parse_views_file(FIXTURE, grants_by_view=grants)
    return [v for v in views if v.fq_name == name][0]


def test_no_where_clause_yields_unrestricted_filter():
    v = _view("sec.finance.v_derived_example")
    entitlements = translate_rls([v])
    assert len(entitlements) == 1
    assert entitlements[0].row_filter_predicate == "TRUE"


def test_and_predicate_carried_through_verbatim():
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    views = parse_views_file(FIXTURE, grants_by_view=grants)
    v = [x for x in views if x.fq_name == "sec.hr.v_employee_basic"][0]
    entitlements = translate_rls([v])
    assert entitlements[0].row_filter_predicate == "dept = 'Engineering' AND active = TRUE"


def test_or_predicate_carried_through_verbatim_for_every_grantee():
    v = _view("sec.sales.v_orders_by_region")
    entitlements = translate_rls([v])

    predicates = {e.principal: e.row_filter_predicate for e in entitlements}
    assert predicates["sales_region_us"] == "region = 'US' OR region = 'CA'"
    assert predicates["sales_region_eu"] == "region = 'US' OR region = 'CA'"


def test_nested_and_or_predicate_carried_through_verbatim():
    v = _view("sec.sales.v_orders_secure")
    entitlements = translate_rls([v])
    assert entitlements[0].row_filter_predicate == (
        "(region = 'US' AND status = 'ACTIVE') OR priority = 'HIGH'"
    )


def test_view_with_no_grantees_produces_no_entitlements():
    v = _view("sec.finance.v_derived_example")
    v.grantees = []
    assert translate_rls([v]) == []
