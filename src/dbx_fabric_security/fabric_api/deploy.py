"""Deployment orchestration: takes the translated Fabric role payloads plus
a target config, and idempotently upserts them via ``FabricApiClient``.

Every role produced by ``role_builder.build_fabric_roles`` is scoped to a
*physical base table* (``role["table"]``, a Databricks-qualified
``catalog.schema.table`` name) -- never to a view. Views are extraction-only
artifacts, used solely to work out what CLS/RLS a table's grantees should
get; nothing here ever deploys a view. See README.md "Target resolution:
tables, not views" for the full rationale.

Target resolution (``resolve_table_target``) assumes the physical table's
*name* is identical in Fabric OneLake as in Databricks (the last segment of
the qualified name, already baked into each role's ``Tables/<name>`` path
by ``role_builder``). That assumption is what lets one *schema*-level
target entry cover every table under it, instead of listing every table by
hand -- see the ``schemas`` key below.

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


def resolve_table_target(table_fqn: str, targets_config: dict) -> tuple[str, str] | None:
    """Resolves a Databricks-qualified table name to ``(workspace_id,
    item_id)`` of the Fabric Lakehouse item that owns it.

    ``targets_config`` has two optional keys:

    - ``"tables"``: exact ``catalog.schema.table`` -> ``{"workspaceId": ..,
      "itemId": ..}``, for a table that needs to land somewhere other than
      its schema's default (or when schemas don't map 1:1 to Lakehouses).
    - ``"schemas"``: ``catalog.schema`` -> ``{"workspaceId": .., "itemId":
      ..}``, applied to every table under that schema that has no exact
      entry in ``"tables"``. Relies on the table-name-parity assumption
      above -- one entry then covers every table Databricks and Fabric
      agree on the name of.

    An exact table entry always wins over a schema default.
    """
    tables = targets_config.get("tables", {})
    if table_fqn in tables:
        entry = tables[table_fqn]
        return entry["workspaceId"], entry["itemId"]

    parts = table_fqn.split(".")
    if len(parts) >= 2:
        schema_fqn = ".".join(parts[:2])
        schemas = targets_config.get("schemas", {})
        if schema_fqn in schemas:
            entry = schemas[schema_fqn]
            return entry["workspaceId"], entry["itemId"]

    return None


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
    targets_config: dict,
) -> list[tuple[DeploymentPlan, FabricApiResult]]:
    """``targets_config`` is resolved per table via ``resolve_table_target``
    (see its docstring for the ``tables``/``schemas`` shape). Tables with no
    configured target -- resolved via neither an exact entry nor their
    schema's default -- are skipped; the caller is responsible for reporting
    which ones and why (see ``cli.cmd_deploy``, which also distinguishes a
    genuinely unmapped table from one that's actually a view).
    """

    by_table: dict[str, list[dict]] = {}
    for role in fabric_roles:
        by_table.setdefault(role["table"], []).append(role)

    results = []
    for table, roles in by_table.items():
        target = resolve_table_target(table, targets_config)
        if target is None:
            continue
        workspace_id, item_id = target
        plan = plan_deployment(client, workspace_id, item_id, table, roles)
        result = apply_deployment(client, plan)
        results.append((plan, result))
    return results
