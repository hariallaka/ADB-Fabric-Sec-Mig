"""Merges CLS + RLS entitlements into deployable Fabric OneLake "Data Access
Role" payloads, one role per (table, AD group) pair.

The payload shape approximates the Fabric REST API's Item Data Access Roles
resource (``PUT /v1/workspaces/{workspaceId}/items/{itemId}/dataAccessRoles``).
That API is evolving (public preview at the time of writing), so the exact
field names here are a best-effort mapping -- see
``docs/technical-assessment.md`` (Fabric API Assessment) for the validation
steps required before this is used against a live tenant.
"""

from __future__ import annotations

import re

from dbx_fabric_security.translator.cls_translator import ClsEntitlement
from dbx_fabric_security.translator.rls_translator import RlsEntitlement


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()


def build_fabric_roles(
    cls_entitlements: list[ClsEntitlement],
    rls_entitlements: list[RlsEntitlement],
    group_directory: dict[str, str] | None = None,
) -> list[dict]:
    """Returns a list of Fabric data-access-role payloads keyed by
    ``(table, ad_group)``. Rows with no AD group (DEFAULT_VISIBLE / plain
    attribute filters) are excluded from role payloads but remain visible
    in the flat CLS/RLS reports for governance review.
    """

    group_directory = group_directory or {}
    keys: set[tuple[str, str]] = set()

    for e in cls_entitlements:
        if e.table and e.ad_group:
            keys.add((e.table, e.ad_group))
    for r in rls_entitlements:
        if r.table and r.ad_group:
            keys.add((r.table, r.ad_group))

    roles = []
    for table, group in sorted(keys):
        permit_columns = sorted(
            {
                e.column
                for e in cls_entitlements
                if e.table == table and e.ad_group == group and e.access_effect == "PERMIT"
            }
        )
        row_filters = sorted(
            {
                r.row_filter_predicate
                for r in rls_entitlements
                if r.table == table and r.ad_group == group
            }
        )
        object_id = group_directory.get(group)

        roles.append(
            {
                "name": f"role_{_slug(table)}_{_slug(group)}",
                "table": table,
                "members": {
                    "microsoftEntraMembers": [
                        {
                            "objectId": object_id or "<UNRESOLVED_AD_GROUP_OBJECT_ID>",
                            "objectType": "Group",
                            "groupName": group,
                        }
                    ]
                },
                "decisionRules": [
                    {
                        "effect": "Permit",
                        "permission": [
                            {
                                "attributeName": "Path",
                                "attributeValueIncludedIn": [f"Tables/{table.split('.')[-1]}"],
                            }
                        ],
                    }
                ],
                "columnRules": {
                    "permit": permit_columns,
                    "note": (
                        "Columns not listed here follow the table's default "
                        "visibility; only columns carrying an explicit "
                        "dynamic-view mask are enumerated."
                        if permit_columns
                        else "No column-level mask found for this group/table; "
                        "table-level access applies to all columns."
                    ),
                },
                "rowFilters": row_filters or ["TRUE"],
                "unresolvedAdGroupObjectId": object_id is None,
            }
        )

    return roles
