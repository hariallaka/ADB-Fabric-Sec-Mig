import os

import pytest

from dbx_fabric_security.extractor.view_parser import parse_views_file

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")


@pytest.fixture(scope="module")
def views():
    return {v.fq_name: v for v in parse_views_file(FIXTURE)}


def test_derived_column_assumption(views):
    """The spike's key design assumption: `c = a * b` must be flagged
    derived, with `a`/`b` as its traced source columns, and CLS must never
    be generated against `c` itself.
    """
    v = views["sec.finance.v_derived_example"]
    assert v.derived_columns == ["c"]

    lineage_by_col = {lin.output_column: lin for lin in v.column_lineage}
    assert lineage_by_col["a"].is_derived is False
    assert lineage_by_col["b"].is_derived is False
    assert lineage_by_col["c"].is_derived is True
    assert sorted(lineage_by_col["c"].source_columns) == ["a", "b"]


def test_cls_mask_extraction(views):
    v = views["sec.hr.v_employee_cls"]
    masks = {m.output_column: m for m in v.column_masks}

    assert masks["salary"].source_column == "salary"
    assert masks["salary"].ad_group == "finance_readers"
    assert masks["salary"].else_value == "NULL"

    assert masks["ssn"].source_column == "ssn"
    assert masks["ssn"].ad_group == "hr_full_access"
    assert masks["ssn"].else_value == "'REDACTED'"

    # emp_id / name are plain pass-through columns, not masks
    assert "emp_id" not in masks
    assert "name" not in masks


def test_group_gate_row_filter(views):
    v = views["sec.hr.v_employee_gated"]
    assert len(v.row_filters) == 1
    rf = v.row_filters[0]
    assert rf.filter_type == "GROUP_GATE"
    assert rf.referenced_ad_groups == ["all_employees_view"]
    assert rf.group_predicates == {"all_employees_view": "TRUE"}


def test_group_attribute_row_filter(views):
    v = views["sec.sales.v_orders_by_region"]
    assert len(v.row_filters) == 1
    rf = v.row_filters[0]
    assert rf.filter_type == "GROUP_ATTRIBUTE"
    assert rf.group_predicates["sales_region_us"] == "region = 'US'"
    assert rf.group_predicates["sales_region_eu"] == "region = 'EU'"


def test_combined_cls_and_rls_view(views):
    v = views["sec.sales.v_orders_secure"]
    assert v.derived_columns == ["total_amount"]
    assert len(v.column_masks) == 1
    assert v.column_masks[0].source_column == "unit_price"
    assert v.column_masks[0].ad_group == "sales_finance"
    assert len(v.row_filters) == 1
    assert v.row_filters[0].filter_type == "GROUP_ATTRIBUTE"


def test_nested_view_flagged(views):
    v = views["sec.hr.v_employee_gated_export"]
    assert v.references_views == ["v_employee_gated"]
    assert any("nested view" in msg for msg in v.unsupported_constructs)


def test_complex_view_flagged(views):
    v = views["sec.sales.v_regional_totals"]
    assert v.is_complex is True
    assert v.base_tables == ["sec.sales.orders", "sec.sales.regions"]
    assert any("JOIN" in msg for msg in v.unsupported_constructs)


def test_user_match_row_filter(views):
    v = views["sec.finance.v_my_expense_reports"]
    assert len(v.row_filters) == 1
    assert v.row_filters[0].filter_type == "USER_MATCH"
    assert v.row_filters[0].referenced_ad_groups == []
