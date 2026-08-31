"""Merges CLS + RLS entitlements into deployable Fabric OneLake "Data Access
Role" payloads, one role per (table, principal) pair.

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
    principal_directory: dict[str, str] | None = None,
) -> list[dict]:
    """Returns a list of Fabric data-access-role payloads keyed by
    ``(table, principal)``. ``principal_directory`` maps a principal name
    (AD group or user) to its Entra object id, typically from an AGS export.
    """

    principal_directory = principal_directory or {}
    keys: set[tuple[str, str]] = set()

    for e in cls_entitlements:
        if e.table:
            keys.add((e.table, e.principal))
    for r in rls_entitlements:
        if r.table:
            keys.add((r.table, r.principal))

    roles = []
    for table, principal in sorted(keys):
        permit_columns = sorted(
            {e.column for e in cls_entitlements if e.table == table and e.principal == principal}
        )
        row_filters = sorted(
            {r.row_filter_predicate for r in rls_entitlements if r.table == table and r.principal == principal}
        )
        object_id = principal_directory.get(principal)

        roles.append(
            {
                "name": f"role_{_slug(table)}_{_slug(principal)}",
                "table": table,
                "members": {
                    "microsoftEntraMembers": [
                        {
                            "objectId": object_id or "<UNRESOLVED_PRINCIPAL_OBJECT_ID>",
                            "objectType": "Group",
                            "principalName": principal,
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
                "columnRules": {"permit": permit_columns},
                "rowFilters": row_filters or ["TRUE"],
                "unresolvedPrincipalObjectId": object_id is None,
            }
        )

    return roles
