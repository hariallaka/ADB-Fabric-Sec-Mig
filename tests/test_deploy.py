import os

from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.fabric_api.client import FabricApiClient
from dbx_fabric_security.fabric_api.deploy import deploy_roles
from dbx_fabric_security.translator.cls_translator import translate_cls
from dbx_fabric_security.translator.rls_translator import translate_rls
from dbx_fabric_security.translator.role_builder import build_fabric_roles

VIEWS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")


def test_dry_run_never_calls_network_and_reports_plan():
    views = parse_views_file(VIEWS_FIXTURE)
    roles = build_fabric_roles(translate_cls(views), translate_rls(views))

    client = FabricApiClient(dry_run=True)  # no token required
    targets = {"sec.hr.employee": ("ws-1", "item-1")}

    results = deploy_roles(client, roles, targets)

    assert len(results) == 1
    plan, result = results[0]
    assert result.dry_run is True
    assert result.status_code is None
    assert plan.workspace_id == "ws-1"
    assert plan.item_id == "item-1"
    assert len(plan.roles_to_apply) >= 1


def test_tables_without_target_mapping_are_skipped():
    views = parse_views_file(VIEWS_FIXTURE)
    roles = build_fabric_roles(translate_cls(views), translate_rls(views))

    client = FabricApiClient(dry_run=True)
    results = deploy_roles(client, roles, table_targets={})

    assert results == []
