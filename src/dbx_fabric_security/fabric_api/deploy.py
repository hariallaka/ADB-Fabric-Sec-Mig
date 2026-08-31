"""Deployment orchestration: takes the translated Fabric role payloads plus
a table -> (workspaceId, itemId) target map, and idempotently upserts them
via ``FabricApiClient``.

Idempotency strategy: this toolkit only owns roles whose name matches the
``role_<table>_<group>`` convention produced by
``translator.role_builder.build_fabric_roles``. On each deploy it GETs the
current role set for a target item, drops any tool-managed role that is no
longer produced by translation (so revoked/renamed grants are cleaned up),
preserves any manually-authored role (anything not matching the naming
convention), and PUTs the merged set back -- since the Data Access Roles API
is a full-replace PUT rather than a incremental patch.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dbx_fabric_security.fabric_api.client import FabricApiClient, FabricApiResult

_MANAGED_PREFIX = "role_"


@dataclass
class DeploymentPlan:
    workspace_id: str
    item_id: str
    table: str
    roles_to_apply: list[dict]
    roles_preserved: list[dict] = field(default_factory=list)
    roles_removed: list[str] = field(default_factory=list)


def plan_deployment(
    client: FabricApiClient,
    workspace_id: str,
    item_id: str,
    table: str,
    desired_roles: list[dict],
) -> DeploymentPlan:
    current = client.get_data_access_roles(workspace_id, item_id)
    existing_roles = []
    if not current.dry_run and current.response_body:
        existing_roles = current.response_body.get("value", [])

    preserved = [r for r in existing_roles if not r.get("name", "").startswith(_MANAGED_PREFIX)]
    removed = [
        r["name"]
        for r in existing_roles
        if r.get("name", "").startswith(_MANAGED_PREFIX)
        and r["name"] not in {d["name"] for d in desired_roles}
    ]

    return DeploymentPlan(
        workspace_id=workspace_id,
        item_id=item_id,
        table=table,
        roles_to_apply=desired_roles + preserved,
        roles_preserved=preserved,
        roles_removed=removed,
    )


def apply_deployment(client: FabricApiClient, plan: DeploymentPlan) -> FabricApiResult:
    return client.put_data_access_roles(plan.workspace_id, plan.item_id, plan.roles_to_apply)


def deploy_roles(
    client: FabricApiClient,
    fabric_roles: list[dict],
    table_targets: dict[str, tuple[str, str]],
) -> list[tuple[DeploymentPlan, FabricApiResult]]:
    """``table_targets`` maps a Databricks-qualified table name (as it
    appears on each role's ``table`` field) to ``(workspace_id, item_id)``
    of the Fabric Lakehouse item that should own the role. Tables with no
    configured target are skipped and reported by the caller.
    """

    by_table: dict[str, list[dict]] = {}
    for role in fabric_roles:
        by_table.setdefault(role["table"], []).append(role)

    results = []
    for table, roles in by_table.items():
        target = table_targets.get(table)
        if target is None:
            continue
        workspace_id, item_id = target
        plan = plan_deployment(client, workspace_id, item_id, table, roles)
        result = apply_deployment(client, plan)
        results.append((plan, result))
    return results
