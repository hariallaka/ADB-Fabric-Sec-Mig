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


def test_fetch_view_grants_dry_run_returns_empty_mapping():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    grants = client.fetch_view_grants("wh-1", catalog="sec", schema="hr")
    assert grants == {}


def test_grants_reconstruction_shape():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)

    class _FakeResult:
        dry_run = False
        response_body = {
            "result": {
                "data_array": [
                    ["sec", "hr", "v_employee_basic", "hr_readers"],
                    ["sec", "hr", "v_employee_basic", "hr_admin"],
                ]
            }
        }

    client.execute_statement = lambda warehouse_id, statement: _FakeResult()  # noqa: E731
    grants = client.fetch_view_grants("wh-1", catalog="sec", schema="hr")

    assert grants == {"sec.hr.v_employee_basic": ["hr_readers", "hr_admin"]}


def test_fetch_principal_object_id_dry_run_returns_unknown():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    object_id, principal_type = client.fetch_principal_object_id("finance_readers")
    assert object_id is None
    assert principal_type == "UNKNOWN"


def test_fetch_principal_directory_dry_run_returns_empty():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    assert client.fetch_principal_directory(["finance_readers", "hr_readers"]) == {}


def test_fetch_principal_object_id_resolves_group_before_user():
    # dry_run=False so the real (non-short-circuited) lookup path runs; the
    # network layer itself is replaced by the stub below, so no call is made.
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=False)
    client._scim_lookup = lambda resource, field, value: (  # noqa: E731
        {"externalId": "grp-object-id"} if resource == "Groups" else {"externalId": "usr-object-id"}
    )
    object_id, principal_type = client.fetch_principal_object_id("finance_readers")
    assert object_id == "grp-object-id"
    assert principal_type == "GROUP"


def test_fetch_principal_object_id_falls_back_to_user():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=False)
    client._scim_lookup = lambda resource, field, value: (  # noqa: E731
        None if resource == "Groups" else {"externalId": "usr-object-id"}
    )
    object_id, principal_type = client.fetch_principal_object_id("jane.doe@example.com")
    assert object_id == "usr-object-id"
    assert principal_type == "USER"


def test_fetch_principal_directory_dedupes_and_skips_unresolved():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    calls = []

    def fake_lookup(name):
        calls.append(name)
        return ("obj-" + name, "GROUP") if name != "ghost_group" else (None, "UNKNOWN")

    client.fetch_principal_object_id = fake_lookup
    directory = client.fetch_principal_directory(["a", "a", "ghost_group", "b"])

    assert calls == ["a", "ghost_group", "b"]  # deduped, order preserved
    assert directory == {"a": "obj-a", "b": "obj-b"}


def test_grant_catalog_access_owner_mode_dry_run():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    result = client.grant_catalog_access("wh-1", "sec", "extraction-sp", mode="owner")
    assert result.dry_run is True
    assert result.payload["statement"] == "ALTER CATALOG `sec` OWNER TO `extraction-sp`"


def test_grant_catalog_access_all_privileges_mode_dry_run():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    result = client.grant_catalog_access("wh-1", "sec", "extraction-sp", mode="all_privileges")
    assert result.payload["statement"] == "GRANT ALL PRIVILEGES ON CATALOG `sec` TO `extraction-sp`"


def test_grant_catalog_access_rejects_bad_mode():
    client = DatabricksApiClient(workspace_url="https://example.azuredatabricks.net", dry_run=True)
    try:
        client.grant_catalog_access("wh-1", "sec", "extraction-sp", mode="bogus")
        assert False, "expected ValueError for invalid mode"
    except ValueError:
        pass


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
