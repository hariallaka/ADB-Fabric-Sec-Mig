"""Flattens generated Fabric roles into the AD Group -> Fabric Role ->
OneLake object report described in the spike scope (section 3, Security
Role Mapping).

No AGS involvement: the principal name and Azure AD object id already
inside each role (from Unity Catalog's own grants, resolved via SCIM --
see ``extractor/databricks_client.fetch_principal_directory`` -- or
supplied directly in an offline grants CSV) are the whole mapping. This
module only exists to turn the nested role payloads into a flat,
reviewable report.
"""

from __future__ import annotations


def build_role_mapping(fabric_roles: list[dict]) -> list[dict]:
    """Produces one row per generated Fabric role: which principal it's
    scoped to, which table/columns/row-filter it grants, and whether that
    principal's Azure AD object id could be resolved.
    """

    mapping_rows = []
    for role in fabric_roles:
        member = role["members"]["microsoftEntraMembers"][0]
        mapping_rows.append(
            {
                "principalName": member["principalName"],
                "principalObjectId": None if role["unresolvedPrincipalObjectId"] else member["objectId"],
                "fabricRoleName": role["name"],
                "oneLakeObject": role["table"],
                "oneLakePath": role["decisionRules"][0]["permission"][0][
                    "attributeValueIncludedIn"
                ][0],
                "columnPermitCount": len(role["columnRules"]["permit"]),
                "rowFilters": role["rowFilters"],
                "unresolvedPrincipalObjectId": role["unresolvedPrincipalObjectId"],
            }
        )
    return mapping_rows
