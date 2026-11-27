"""AD group -> Fabric database role mapping, and the per-view SELECT grants
that follow from it.

Mapping CSV columns:

* ``ad_group`` (required): the principal name exactly as it appears in the
  Databricks grants output (``principal`` column). Matching is exact (after
  trimming whitespace). It is never case-folded or fuzzy-matched, so a typo
  leaves the group unmapped rather than mapping it to the wrong role.
* ``fabric_role`` (required): the Fabric database role to create.
* ``fabric_principal`` (optional): the name Fabric should use for the
  group in ``ALTER ROLE ... ADD MEMBER``, if it differs from the Databricks
  name. Defaults to ``ad_group``.

One AD group can map to several roles, and one role can hold several
groups. Grants are computed per view: a role gets ``SELECT`` on a view when
any group mapped to it holds ``SELECT`` on that view in Unity Catalog. A
grantee with no mapping row gets nothing (fail closed) and is reported.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field

from dbx_fabric_security.fabric_sql.admin_views import AdminView
from dbx_fabric_security.fabric_sql.views import FabricViewScript


@dataclass
class RoleMapping:
    ad_group: str
    fabric_role: str
    fabric_principal: str


def parse_role_mapping_csv(path: str) -> list[RoleMapping]:
    rows: list[RoleMapping] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"ad_group", "fabric_role"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Role mapping CSV {path} is missing column(s): {sorted(missing)}")
        for i, row in enumerate(reader, start=2):
            group = (row.get("ad_group") or "").strip()
            role = (row.get("fabric_role") or "").strip()
            if not group and not role:
                continue
            if not group or not role:
                raise ValueError(f"Role mapping CSV {path} line {i}: ad_group and fabric_role are both required")
            principal = (row.get("fabric_principal") or "").strip() or group
            mapping = RoleMapping(group, role, principal)
            if mapping not in rows:
                rows.append(mapping)
    return rows


@dataclass
class RolePlan:
    # role -> sorted Fabric principal names to add as members
    role_members: dict[str, list[str]] = field(default_factory=dict)
    # role -> target view names ([schema].[view]) to GRANT SELECT on, per catalog
    role_grants: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # (view, grantee) pairs where the grantee has no mapping row
    unmapped_grantees: list[dict] = field(default_factory=list)
    # views that are not deployable, with grantees who therefore get nothing
    withheld_grants: list[dict] = field(default_factory=list)
    # roles whose member groups had different view access in Databricks
    overgrant_warnings: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # flat audit rows: view, ad_group, fabric_role, status
    grant_rows: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "roleMembers": self.role_members,
            "roleGrants": self.role_grants,
            "unmappedGrantees": self.unmapped_grantees,
            "withheldGrants": self.withheld_grants,
            "overgrantWarnings": self.overgrant_warnings,
            "warnings": self.warnings,
        }


def build_role_plan(
    scripts: list[FabricViewScript],
    mappings: list[RoleMapping],
    admin_views: list[AdminView],
    admin_role: str,
) -> RolePlan:
    plan = RolePlan()
    roles_by_group: dict[str, list[RoleMapping]] = {}
    for m in mappings:
        roles_by_group.setdefault(m.ad_group, []).append(m)

    grants: dict[str, dict[str, set[str]]] = {}
    members: dict[str, set[str]] = {}
    views_by_group: dict[str, set[str]] = {}

    for script in scripts:
        for grantee in script.grantees:
            views_by_group.setdefault(grantee, set()).add(script.source_view)
            role_maps = roles_by_group.get(grantee, [])
            if not role_maps:
                plan.unmapped_grantees.append({"view": script.source_view, "adGroup": grantee})
                plan.grant_rows.append({
                    "view": script.source_view, "targetView": script.target_name,
                    "adGroup": grantee, "fabricRole": "", "status": "unmapped_grantee",
                })
                continue
            for m in role_maps:
                if not script.deployable:
                    plan.grant_rows.append({
                        "view": script.source_view, "targetView": script.target_name,
                        "adGroup": grantee, "fabricRole": m.fabric_role, "status": "withheld_view_needs_review",
                    })
                    continue
                members.setdefault(m.fabric_role, set()).add(m.fabric_principal)
                grants.setdefault(m.fabric_role, {}).setdefault(script.catalog, set()).add(script.target_name)
                plan.grant_rows.append({
                    "view": script.source_view, "targetView": script.target_name,
                    "adGroup": grantee, "fabricRole": m.fabric_role, "status": "granted",
                })
        if not script.deployable and script.grantees:
            plan.withheld_grants.append({"view": script.source_view, "grantees": list(script.grantees)})

    admin_members = {m.fabric_principal for m in mappings if m.fabric_role == admin_role}
    if admin_views:
        if not admin_members:
            plan.warnings.append(
                f"Admin role '{admin_role}' has no AD group in the role mapping CSV; its views "
                f"and grants are generated but nobody will be a member."
            )
        members.setdefault(admin_role, set()).update(admin_members)
        for av in admin_views:
            grants.setdefault(admin_role, {}).setdefault(av.catalog, set()).add(av.target_name)
            for principal in sorted(admin_members):
                plan.grant_rows.append({
                    "view": f"(admin) {av.base_table}", "targetView": av.target_name,
                    "adGroup": principal, "fabricRole": admin_role, "status": "granted",
                })

    # A role shared by groups that had *different* views in Databricks
    # gives every member the union of those views.
    groups_by_role: dict[str, set[str]] = {}
    for m in mappings:
        groups_by_role.setdefault(m.fabric_role, set()).add(m.ad_group)
    for role, groups in sorted(groups_by_role.items()):
        if role == admin_role:
            continue
        access = {g: frozenset(views_by_group.get(g, set())) for g in groups if g in views_by_group}
        if len(set(access.values())) > 1:
            plan.overgrant_warnings.append({
                "fabricRole": role,
                "detail": "Member groups had different view access in Databricks; every member "
                          "now gets the union.",
                "viewsByGroup": {g: sorted(v) for g, v in sorted(access.items())},
            })

    plan.role_members = {r: sorted(m) for r, m in sorted(members.items())}
    plan.role_grants = {
        r: {c: sorted(v) for c, v in sorted(by_cat.items())} for r, by_cat in sorted(grants.items())
    }
    return plan
