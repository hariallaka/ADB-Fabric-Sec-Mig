import os

from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.fabric_api.client import FabricApiClient
from dbx_fabric_security.fabric_api.deploy import deploy_roles, resolve_table_target
from dbx_fabric_security.translator.cls_translator import translate_cls
from dbx_fabric_security.translator.rls_translator import translate_rls
from dbx_fabric_security.translator.role_builder import build_fabric_roles

VIEWS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_views.sql")
GRANTS_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "grants_sample.csv")


def _roles():
    grants, _principal_dir = parse_grants_csv(GRANTS_FIXTURE)
    views = parse_views_file(VIEWS_FIXTURE, grants_by_view=grants)
    return build_fabric_roles(translate_cls(views), translate_rls(views))


def test_dry_run_never_calls_network_and_reports_plan():
    client = FabricApiClient(dry_run=True)  # no token required
    targets = {"tables": {"sec.finance.table1": {"workspaceId": "ws-1", "itemId": "item-1"}}}

    results = deploy_roles(client, _roles(), targets)

    assert len(results) == 1
    plan, result = results[0]
    assert result.dry_run is True
    assert result.status_code is None
    assert plan.workspace_id == "ws-1"
    assert plan.item_id == "item-1"
    assert len(plan.roles_to_apply) >= 1


def test_tables_without_target_mapping_are_skipped():
    client = FabricApiClient(dry_run=True)
    results = deploy_roles(client, _roles(), targets_config={})
    assert results == []


def test_schema_level_default_covers_every_table_in_it():
    """This is the table-name-parity payoff: one 'sec.finance' schema entry
    should cover both sec.finance.table1 and sec.finance.expense_reports
    without listing either by name.
    """
    client = FabricApiClient(dry_run=True)
    targets = {"schemas": {"sec.finance": {"workspaceId": "ws-1", "itemId": "item-1"}}}

    results = deploy_roles(client, _roles(), targets)

    tables_deployed = {plan.table for plan, _ in results}
    assert tables_deployed == {"sec.finance.table1", "sec.finance.expense_reports"}
    assert all(plan.workspace_id == "ws-1" and plan.item_id == "item-1" for plan, _ in results)


def test_exact_table_entry_overrides_schema_default():
    client = FabricApiClient(dry_run=True)
    targets = {
        "schemas": {"sec.finance": {"workspaceId": "schema-ws", "itemId": "schema-item"}},
        "tables": {"sec.finance.table1": {"workspaceId": "override-ws", "itemId": "override-item"}},
    }

    results = deploy_roles(client, _roles(), targets)
    by_table = {plan.table: plan for plan, _ in results}

    assert by_table["sec.finance.table1"].workspace_id == "override-ws"
    assert by_table["sec.finance.expense_reports"].workspace_id == "schema-ws"


class TestResolveTableTarget:
    def test_exact_match_wins_over_schema(self):
        config = {
            "schemas": {"sec.finance": {"workspaceId": "schema-ws", "itemId": "schema-item"}},
            "tables": {"sec.finance.table1": {"workspaceId": "table-ws", "itemId": "table-item"}},
        }
        assert resolve_table_target("sec.finance.table1", config) == ("table-ws", "table-item")

    def test_falls_back_to_schema_default(self):
        config = {"schemas": {"sec.finance": {"workspaceId": "schema-ws", "itemId": "schema-item"}}}
        assert resolve_table_target("sec.finance.table1", config) == ("schema-ws", "schema-item")

    def test_no_match_returns_none(self):
        config = {"schemas": {"sec.hr": {"workspaceId": "hr-ws", "itemId": "hr-item"}}}
        assert resolve_table_target("sec.finance.table1", config) is None

    def test_empty_config_returns_none(self):
        assert resolve_table_target("sec.finance.table1", {}) is None
