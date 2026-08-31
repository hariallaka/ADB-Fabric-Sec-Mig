"""Thin wrapper around the Fabric REST API surface relevant to this spike.

Two API families are involved:

1. **Item Data Access Roles** -- OneLake-level RBAC for a Lakehouse item,
   supporting table/folder scoping plus row and column decision rules. This
   is the primary provisioning target for the roles this toolkit builds.
   ``PUT/GET /v1/workspaces/{workspaceId}/items/{itemId}/dataAccessRoles``
2. **Core workspace/item lookups**, used to resolve a Lakehouse's item id
   from its display name before role calls.

The Data Access Roles API was in public preview at the time this spike was
written; the exact request/response schema should be re-validated against
the current Microsoft Fabric REST API documentation before this client is
pointed at a real tenant (see docs/technical-assessment.md, "Fabric API
Assessment").

This client performs no network calls unless it is explicitly given a
bearer token and ``dry_run=False`` -- every method defaults to a safe,
side-effect-free dry run that only returns the request that *would* be
sent, which is what the CLI and Azure DevOps pipeline use for review gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"


@dataclass
class FabricApiResult:
    method: str
    url: str
    payload: dict | None
    dry_run: bool
    status_code: int | None = None
    response_body: Any = None


class FabricApiClient:
    def __init__(self, bearer_token: str | None = None, dry_run: bool = True, timeout: int = 30):
        self.bearer_token = bearer_token
        self.dry_run = dry_run
        self.timeout = timeout

    def _headers(self) -> dict:
        if not self.bearer_token:
            raise RuntimeError(
                "FabricApiClient requires a bearer_token for live calls; "
                "obtain one via an Azure AD app registration with Fabric API "
                "permissions (client-credentials or on-behalf-of flow)."
            )
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }

    def _call(self, method: str, url: str, payload: dict | None = None) -> FabricApiResult:
        if self.dry_run:
            return FabricApiResult(method=method, url=url, payload=payload, dry_run=True)

        resp = requests.request(
            method, url, headers=self._headers(), json=payload, timeout=self.timeout
        )
        body = None
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        return FabricApiResult(
            method=method,
            url=url,
            payload=payload,
            dry_run=False,
            status_code=resp.status_code,
            response_body=body,
        )

    def get_data_access_roles(self, workspace_id: str, item_id: str) -> FabricApiResult:
        url = f"{FABRIC_API_BASE}/workspaces/{workspace_id}/items/{item_id}/dataAccessRoles"
        return self._call("GET", url)

    def put_data_access_roles(
        self, workspace_id: str, item_id: str, roles: list[dict]
    ) -> FabricApiResult:
        """Upserts the full set of data access roles for a Lakehouse item.

        The API is a full-replace PUT, not an incremental patch -- callers
        should GET the current roles first and merge in roles this toolkit
        does not manage (e.g. manually-authored roles) before calling this.
        """
        url = f"{FABRIC_API_BASE}/workspaces/{workspace_id}/items/{item_id}/dataAccessRoles"
        return self._call("PUT", url, {"value": roles})

    def list_workspace_items(self, workspace_id: str, item_type: str = "Lakehouse") -> FabricApiResult:
        url = f"{FABRIC_API_BASE}/workspaces/{workspace_id}/items?type={item_type}"
        return self._call("GET", url)
