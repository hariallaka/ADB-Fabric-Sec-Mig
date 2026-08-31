import os

from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.translator.cls_translator import translate_cls

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")


def test_derived_column_never_gets_direct_entitlement():
    views = parse_views_file(FIXTURE)
    view = [v for v in views if v.fq_name == "sec.finance.v_derived_example"][0]
    entitlements = translate_cls([view])

    columns_with_entitlements = {e.column for e in entitlements}
    assert "c" not in columns_with_entitlements

    derived_source_entries = [e for e in entitlements if e.source_type == "DERIVED_SOURCE"]
    assert {e.column for e in derived_source_entries} == {"a", "b"}
    assert all(e.derived_output_column == "c" for e in derived_source_entries)
    assert all(e.ad_group is None for e in derived_source_entries)


def test_masked_columns_produce_permit_entitlements():
    views = parse_views_file(FIXTURE)
    view = [v for v in views if v.fq_name == "sec.hr.v_employee_cls"][0]
    entitlements = translate_cls([view])

    permits = {(e.column, e.ad_group) for e in entitlements if e.access_effect == "PERMIT"}
    assert ("salary", "finance_readers") in permits
    assert ("ssn", "hr_full_access") in permits

    salary_entry = [e for e in entitlements if e.column == "salary"][0]
    assert salary_entry.mask_else_value == "NULL"
    assert salary_entry.table == "sec.hr.employee"


def test_plain_columns_are_default_visible():
    views = parse_views_file(FIXTURE)
    view = [v for v in views if v.fq_name == "sec.hr.v_employee_cls"][0]
    entitlements = translate_cls([view])

    emp_id_entry = [e for e in entitlements if e.column == "emp_id"][0]
    assert emp_id_entry.access_effect == "DEFAULT_VISIBLE"
    assert emp_id_entry.source_type == "DIRECT"
