from dbx_fabric_security.extractor.databricks_client import DatabricksApiClient


def test_dry_run_never_calls_network_and_returns_empty():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    result = client.execute_statement("wh-1", "SELECT 1")
    assert result.dry_run is True
    assert result.status_code is None


def test_fetch_view_ddl_dry_run_returns_empty_mapping():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    ddl = client.fetch_view_ddl("wh-1", catalog="sec", schema="hr")
    assert ddl == {}


def test_missing_token_raises_on_live_call():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=False)
    try:
        client.execute_statement("wh-1", "SELECT 1")
        assert False, "expected RuntimeError for missing bearer token"
    except RuntimeError as exc:
        assert "bearer_token" in str(exc)


def test_ddl_reconstruction_shape():
    """fetch_view_ddl composes a CREATE OR REPLACE VIEW statement from
    (catalog, schema, view_name, view_definition) rows -- exercised directly
    against the private assembly logic without a network call by feeding a
    pre-built response through a dry-run-bypassing stub.
    """
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)

    class _FakeResult:
        dry_run = False
        response_body = {
            "result": {
                "data_array": [
                    ["sec", "hr", "v_employee_cls", "SELECT emp_id, name FROM sec.hr.employee"],
                ]
            }
        }

    client.execute_statement = lambda warehouse_id, statement: _FakeResult()  # noqa: E731
    ddl = client.fetch_view_ddl("wh-1", catalog="sec", schema="hr")

    assert set(ddl.keys()) == {"sec.hr.v_employee_cls"}
    assert ddl["sec.hr.v_employee_cls"].startswith("CREATE OR REPLACE VIEW sec.hr.v_employee_cls AS")
    assert "SELECT emp_id, name FROM sec.hr.employee" in ddl["sec.hr.v_employee_cls"]
