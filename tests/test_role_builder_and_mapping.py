import os

from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.mapping.role_mapper import (
    build_role_mapping,
    group_directory,
    load_ags_export,
)
from dbx_fabric_security.translator.cls_translator import translate_cls
from dbx_fabric_security.translator.rls_translator import translate_rls
from dbx_fabric_security.translator.role_builder import build_fabric_roles

VIEWS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
AGS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "ags_export_sample.csv")


def _translate_all():
    views = parse_views_file(VIEWS_FIXTURE)
    return translate_cls(views), translate_rls(views), views


def test_role_builder_merges_cls_and_rls_per_table_and_group():
    cls_e, rls_e, _ = _translate_all()
    ags = load_ags_export(AGS_FIXTURE)
    roles = build_fabric_roles(cls_e, rls_e, group_directory(ags))

    hr_finance_role = [
        r for r in roles if r["table"] == "sec.hr.employee" and "finance_readers" in r["name"]
    ]
    assert len(hr_finance_role) == 1
    role = hr_finance_role[0]
    assert "salary" in role["columnRules"]["permit"]
    assert role["members"]["microsoftEntraMembers"][0]["objectId"] == ags["finance_readers"].ad_group_object_id
    assert role["unresolvedAdGroupObjectId"] is False


def test_role_builder_flags_unresolved_group():
    cls_e, rls_e, _ = _translate_all()
    # Deliberately incomplete directory -> object id should be marked unresolved.
    roles = build_fabric_roles(cls_e, rls_e, group_directory={})
    assert all(r["unresolvedAdGroupObjectId"] for r in roles)
    assert all(
        r["members"]["microsoftEntraMembers"][0]["objectId"] == "<UNRESOLVED_AD_GROUP_OBJECT_ID>"
        for r in roles
    )


def test_role_mapping_ties_ags_to_fabric_role():
    cls_e, rls_e, _ = _translate_all()
    ags = load_ags_export(AGS_FIXTURE)
    roles = build_fabric_roles(cls_e, rls_e, group_directory(ags))
    mapping = build_role_mapping(roles, ags)

    finance_row = [m for m in mapping if m["adGroupName"] == "finance_readers"][0]
    assert finance_row["agsId"] == "AGS-1001"
    assert finance_row["identitySourceOfTruth"] == "AGS"
    assert finance_row["unresolvedAdGroup"] is False
