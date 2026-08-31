"""Pulls view DDL directly out of a live Unity Catalog via the Databricks
Statement Execution API, so extraction can run as its own step -- on its own
schedule, with its own (Databricks-scoped) identity -- decoupled from the
Fabric-side translate/deploy steps.

Deliberately REST-only (no ODBC/JDBC driver, no live Spark session
required): the same client works from an Azure DevOps agent, a Databricks
Job "Python script" task, or a developer's laptop, as long as it can reach
the workspace URL and holds a bearer token (a PAT, or an Azure AD token for
a service principal -- Databricks accepts both as a standard `Authorization:
Bearer` header).

Like ``FabricApiClient``, this defaults to a network-free dry run; a caller
must explicitly pass a token and ``dry_run=False`` to hit a real workspace.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests

_STATEMENTS_PATH = "/api/2.0/sql/statements"


@dataclass
class DatabricksApiResult:
    method: str
    url: str
    payload: dict | None
    dry_run: bool
    status_code: int | None = None
    response_body: Any = None


class DatabricksApiClient:
    def __init__(
        self,
        workspace_url: str,
        bearer_token: str | None = None,
        dry_run: bool = True,
        timeout: int = 30,
        poll_interval_seconds: float = 2.0,
        poll_timeout_seconds: float = 120.0,
    ):
        self.workspace_url = workspace_url.rstrip("/")
        self.bearer_token = bearer_token
        self.dry_run = dry_run
        self.timeout = timeout
        self.poll_interval_seconds = poll_interval_seconds
        self.poll_timeout_seconds = poll_timeout_seconds

    def _headers(self) -> dict:
        if not self.bearer_token:
            raise RuntimeError(
                "DatabricksApiClient requires a bearer_token for live calls "
                "(a personal access token, or an Azure AD access token for a "
                "service principal registered in the workspace)."
            )
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }

    def execute_statement(self, warehouse_id: str, statement: str) -> DatabricksApiResult:
        """Runs one SQL statement to completion (INLINE/JSON_ARRAY disposition)
        and returns the raw Statement Execution API response.

        Note: this uses the default INLINE result disposition, which is
        sufficient for information_schema-sized result sets but does not
        follow EXTERNAL_LINKS pagination for very large result sets -- see
        docs/limitations.md.
        """
        url = f"{self.workspace_url}{_STATEMENTS_PATH}"
        payload = {"warehouse_id": warehouse_id, "statement": statement, "wait_timeout": "30s"}

        if self.dry_run:
            return DatabricksApiResult(method="POST", url=url, payload=payload, dry_run=True)

        resp = requests.post(url, headers=self._headers(), json=payload, timeout=self.timeout)
        body = resp.json()
        statement_id = body.get("statement_id")
        status = body.get("status", {}).get("state")

        deadline = time.monotonic() + self.poll_timeout_seconds
        while status in ("PENDING", "RUNNING") and time.monotonic() < deadline:
            time.sleep(self.poll_interval_seconds)
            poll_url = f"{self.workspace_url}{_STATEMENTS_PATH}/{statement_id}"
            resp = requests.get(poll_url, headers=self._headers(), timeout=self.timeout)
            body = resp.json()
            status = body.get("status", {}).get("state")

        if status != "SUCCEEDED":
            raise RuntimeError(
                f"Databricks statement {statement_id} did not succeed "
                f"(status={status}): {body.get('status')}"
            )

        return DatabricksApiResult(
            method="POST", url=url, payload=payload, dry_run=False,
            status_code=resp.status_code, response_body=body,
        )

    def fetch_view_ddl(
        self, warehouse_id: str, catalog: str, schema: str | None = None
    ) -> dict[str, str]:
        """Returns ``{fully_qualified_view_name: reconstructed_create_view_sql}``
        for every view in the given catalog (optionally restricted to one
        schema), by reading ``<catalog>.information_schema.views``.

        Reading ``view_definition`` requires the caller to already hold
        SELECT/BROWSE on each view (or be its owner) -- Unity Catalog does
        not expose a view's SQL body to a caller who only has USE CATALOG /
        USE SCHEMA. See README.md's "Databricks RBAC" section.
        """
        where = f"table_schema = '{schema}'" if schema else "1=1"
        statement = (
            "SELECT table_catalog, table_schema, table_name, view_definition "
            f"FROM {catalog}.information_schema.views WHERE {where}"
        )
        result = self.execute_statement(warehouse_id, statement)
        if result.dry_run:
            return {}

        rows = result.response_body.get("result", {}).get("data_array", [])
        ddl_by_view: dict[str, str] = {}
        for cat, sch, name, view_definition in rows:
            fq_name = f"{cat}.{sch}.{name}"
            ddl_by_view[fq_name] = f"CREATE OR REPLACE VIEW {fq_name} AS\n{view_definition}"
        return ddl_by_view

    def fetch_view_grants(
        self, warehouse_id: str, catalog: str, schema: str | None = None
    ) -> dict[str, list[str]]:
        """Returns ``{fully_qualified_view_name: [principal, ...]}`` for every
        principal (AD group or user) holding ``SELECT`` on a view in the
        given catalog. This is the source of truth for who gets CLS/RLS
        access -- it is never inferred from the view's SQL text.

        Joins ``information_schema.table_privileges`` to
        ``information_schema.views`` so only view grants are returned (a
        SELECT grant on a physical table is out of this toolkit's scope).
        """
        where = f"v.table_schema = '{schema}'" if schema else "1=1"
        statement = (
            "SELECT v.table_catalog, v.table_schema, v.table_name, p.grantee "
            f"FROM {catalog}.information_schema.table_privileges p "
            f"JOIN {catalog}.information_schema.views v "
            "  ON p.table_catalog = v.table_catalog "
            "  AND p.table_schema = v.table_schema "
            "  AND p.table_name = v.table_name "
            f"WHERE p.privilege_type = 'SELECT' AND {where}"
        )
        result = self.execute_statement(warehouse_id, statement)
        if result.dry_run:
            return {}

        rows = result.response_body.get("result", {}).get("data_array", [])
        grants_by_view: dict[str, list[str]] = {}
        for cat, sch, name, grantee in rows:
            fq_name = f"{cat}.{sch}.{name}"
            grants_by_view.setdefault(fq_name, [])
            if grantee not in grants_by_view[fq_name]:
                grants_by_view[fq_name].append(grantee)
        return grants_by_view

    def fetch_table_columns(self, warehouse_id: str, table_fqns: list[str]) -> dict[str, list[str]]:
        """Returns ``{catalog.schema.table: [column_name, ...]}`` for the
        given fully-qualified base tables, via each referenced catalog's
        ``information_schema.columns``.

        This is what makes column-to-table attribution for a joined view
        deterministic rather than a guess: an unqualified column in a view's
        SELECT list can be matched against each candidate table's real
        column list (see ``view_parser._resolve_select_columns``). Requests
        are batched one query per distinct catalog among ``table_fqns``.
        """
        by_catalog: dict[str, list[str]] = {}
        for fqn in table_fqns:
            parts = fqn.split(".")
            if len(parts) != 3:
                continue
            catalog, schema, table = parts
            by_catalog.setdefault(catalog, []).append(f"{schema}.{table}")

        columns_by_table: dict[str, list[str]] = {}
        for catalog, schema_tables in by_catalog.items():
            quoted = ", ".join("'" + st.replace("'", "''") + "'" for st in schema_tables)
            statement = (
                "SELECT table_catalog, table_schema, table_name, column_name "
                f"FROM {catalog}.information_schema.columns "
                f"WHERE CONCAT(table_schema, '.', table_name) IN ({quoted}) "
                "ORDER BY ordinal_position"
            )
            result = self.execute_statement(warehouse_id, statement)
            if result.dry_run:
                continue

            rows = result.response_body.get("result", {}).get("data_array", [])
            for cat, sch, name, column_name in rows:
                fq_name = f"{cat}.{sch}.{name}"
                columns_by_table.setdefault(fq_name, []).append(column_name)

        return columns_by_table

    def _scim_lookup(self, resource: str, filter_field: str, value: str) -> dict | None:
        url = f"{self.workspace_url}/api/2.0/preview/scim/v2/{resource}"
        escaped = value.replace('"', '\\"')
        resp = requests.get(
            url, headers=self._headers(), params={"filter": f'{filter_field} eq "{escaped}"'}, timeout=self.timeout
        )
        resp.raise_for_status()
        resources = resp.json().get("Resources", [])
        return resources[0] if resources else None

    def fetch_principal_object_id(self, principal_name: str) -> tuple[str | None, str]:
        """Resolves a Unity Catalog grantee name to its Azure AD object id via
        the workspace SCIM API. Tries Groups first (``externalId``, populated
        when the group is synced from Azure AD via SCIM provisioning), then
        Users. Returns ``(object_id_or_None, principal_type)`` where
        ``principal_type`` is ``"GROUP"``, ``"USER"``, or ``"UNKNOWN"`` if
        neither SCIM lookup matched.

        Requires the caller to have SCIM read access -- typically workspace
        admin. See README.md's "Databricks RBAC" section.
        """
        if self.dry_run:
            return None, "UNKNOWN"

        group = self._scim_lookup("Groups", "displayName", principal_name)
        if group:
            return group.get("externalId"), "GROUP"

        user = self._scim_lookup("Users", "userName", principal_name)
        if user:
            return user.get("externalId"), "USER"

        return None, "UNKNOWN"

    def fetch_principal_directory(self, principal_names: list[str]) -> dict[str, str]:
        """Resolves a batch of grantee names to their Azure AD object ids
        (one SCIM lookup per unique name). Names that resolve to neither a
        group nor a user are omitted -- callers should treat a missing name
        as unresolved (see ``role_builder.build_fabric_roles``'s
        ``unresolvedPrincipalObjectId`` flag).
        """
        directory: dict[str, str] = {}
        for name in dict.fromkeys(principal_names):  # de-dupe, preserve order
            object_id, _principal_type = self.fetch_principal_object_id(name)
            if object_id:
                directory[name] = object_id
        return directory

    def grant_catalog_access(
        self, warehouse_id: str, catalog: str, principal: str, mode: str = "owner"
    ) -> DatabricksApiResult:
        """One-time bootstrap: makes ``principal`` (the extraction service
        principal) able to see *every* view's definition and *every*
        principal's grants in ``catalog`` via ``information_schema`` --
        ``SELECT`` on a view alone only reveals that view's own definition,
        and ``information_schema.table_privileges`` only surfaces grants the
        caller is entitled to see (owner, a MANAGE holder, or an admin). See
        README.md's "Databricks RBAC" section for why this is needed.

        Must be run by a catalog owner or metastore admin -- never by the
        extraction service principal itself, which doesn't have this
        privilege yet. ``mode="owner"`` transfers catalog ownership;
        ``mode="all_privileges"`` grants ALL PRIVILEGES without changing the
        owner. Dry-run by default like every other call on this client.
        """
        if mode not in ("owner", "all_privileges"):
            raise ValueError("mode must be 'owner' or 'all_privileges'")

        principal_ident = principal.replace("`", "")
        if mode == "owner":
            statement = f"ALTER CATALOG `{catalog}` OWNER TO `{principal_ident}`"
        else:
            statement = f"GRANT ALL PRIVILEGES ON CATALOG `{catalog}` TO `{principal_ident}`"

        return self.execute_statement(warehouse_id, statement)
