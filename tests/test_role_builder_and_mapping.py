import os

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.mapping.role_mapper import build_role_mapping
from dbx_fabric_security.translator.cls_translator import translate_cls
from dbx_fabric_security.translator.rls_translator import translate_rls
from dbx_fabric_security.translator.role_builder import build_fabric_roles

VIEWS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")


def _translate_all():
    grants_by_view, principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    views = parse_views_file(VIEWS_FIXTURE, grants_by_view=grants_by_view)
    return translate_cls(views), translate_rls(views), principal_dir


def test_role_builder_merges_cls_and_rls_per_table_and_principal():
    cls_e, rls_e, principal_dir = _translate_all()
    roles = build_fabric_roles(cls_e, rls_e, principal_dir)

    finance_role = [
        r for r in roles if r["table"] == "sec.finance.table1" and "finance_readers" in r["name"]
    ]
    assert len(finance_role) == 1
    role = finance_role[0]
    assert role["columnRules"]["permit"] == ["a", "b"]
    assert role["rowFilters"] == ["TRUE"]
    assert role["members"]["microsoftEntraMembers"][0]["objectId"] == principal_dir["finance_readers"]
    assert role["unresolvedPrincipalObjectId"] is False


def test_or_predicate_role_carries_full_predicate():
    cls_e, rls_e, _ = _translate_all()
    roles = build_fabric_roles(cls_e, rls_e, {})
    role = [r for r in roles if r["table"] == "sec.sales.orders" and "sales_region_us" in r["name"]][0]
    assert role["rowFilters"] == ["region = 'US' OR region = 'CA'"]


def test_role_builder_flags_unresolved_principal():
    cls_e, rls_e, _ = _translate_all()
    roles = build_fabric_roles(cls_e, rls_e, principal_directory={})
    assert all(r["unresolvedPrincipalObjectId"] for r in roles)
    assert all(
        r["members"]["microsoftEntraMembers"][0]["objectId"] == "<UNRESOLVED_PRINCIPAL_OBJECT_ID>"
        for r in roles
    )


def test_grants_csv_principal_without_object_id_is_unresolved():
    """hr_contractor is granted SELECT in the fixture with a blank
    principal_object_id column -- it must come through as unresolved, not
    silently dropped or crash the pipeline.
    """
    cls_e, rls_e, principal_dir = _translate_all()
    assert "hr_contractor" not in principal_dir
    roles = build_fabric_roles(cls_e, rls_e, principal_dir)
    contractor_role = [r for r in roles if "hr_contractor" in r["name"]][0]
    assert contractor_role["unresolvedPrincipalObjectId"] is True


def test_role_mapping_flattens_roles_with_no_ags_involved():
    cls_e, rls_e, principal_dir = _translate_all()
    roles = build_fabric_roles(cls_e, rls_e, principal_dir)
    mapping = build_role_mapping(roles)

    # finance_readers has SELECT on two views over two different tables
    # (v_derived_example -> table1, v_my_expense_reports -> expense_reports),
    # so it legitimately gets one Fabric role per table.
    finance_rows = [m for m in mapping if m["principalName"] == "finance_readers"]
    assert {r["oneLakeObject"] for r in finance_rows} == {
        "sec.finance.table1",
        "sec.finance.expense_reports",
    }
    assert all(r["principalObjectId"] == principal_dir["finance_readers"] for r in finance_rows)
    assert all(r["unresolvedPrincipalObjectId"] is False for r in finance_rows)

    contractor_rows = [m for m in mapping if m["principalName"] == "hr_contractor"]
    assert len(contractor_rows) == 1
    assert contractor_rows[0]["principalObjectId"] is None
    assert contractor_rows[0]["unresolvedPrincipalObjectId"] is True
