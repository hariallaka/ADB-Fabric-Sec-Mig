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
