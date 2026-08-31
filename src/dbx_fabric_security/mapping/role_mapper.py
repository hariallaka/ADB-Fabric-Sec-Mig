"""Builds the AGS -> AD Group -> Fabric Role -> OneLake object mapping model
described in the spike scope (section 3, Security Role Mapping).

AGS (the AD-Group-Sync governance system) remains the authoritative source
of identity: this module never creates or edits AD groups or AGS
memberships. It only maps AGS-managed groups onto the Fabric roles that the
translator layer derives from Databricks view definitions, so that Fabric
role membership can be kept in sync declaratively (e.g. via a scheduled
Azure DevOps pipeline run) instead of being maintained by hand.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass


@dataclass
class AgsGroupRecord:
    ags_id: str
    ags_name: str
    ad_group_name: str
    ad_group_object_id: str


def load_ags_export(path: str) -> dict[str, AgsGroupRecord]:
    """Loads an AGS export CSV (columns: ags_id, ags_name, ad_group_name,
    ad_group_object_id) keyed by ``ad_group_name``.
    """

    records: dict[str, AgsGroupRecord] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rec = AgsGroupRecord(
                ags_id=row["ags_id"].strip(),
                ags_name=row["ags_name"].strip(),
                ad_group_name=row["ad_group_name"].strip(),
                ad_group_object_id=row["ad_group_object_id"].strip(),
            )
            records[rec.ad_group_name] = rec
    return records


def group_directory(ags_records: dict[str, AgsGroupRecord]) -> dict[str, str]:
    """Convenience view: ad_group_name -> ad_group_object_id."""

    return {name: rec.ad_group_object_id for name, rec in ags_records.items()}


def build_role_mapping(
    fabric_roles: list[dict],
    ags_records: dict[str, AgsGroupRecord],
) -> list[dict]:
    """Produces the AGS -> AD Group -> Fabric Role -> OneLake object mapping
    table, one row per generated Fabric role.
    """

    mapping_rows = []
    for role in fabric_roles:
        group_name = role["members"]["microsoftEntraMembers"][0]["groupName"]
        ags = ags_records.get(group_name)
        mapping_rows.append(
            {
                "agsId": ags.ags_id if ags else None,
                "agsName": ags.ags_name if ags else None,
                "adGroupName": group_name,
                "adGroupObjectId": ags.ad_group_object_id if ags else None,
                "fabricRoleName": role["name"],
                "oneLakeObject": role["table"],
                "oneLakePath": role["decisionRules"][0]["permission"][0][
                    "attributeValueIncludedIn"
                ][0],
                "columnPermitCount": len(role["columnRules"]["permit"]),
                "rowFilters": role["rowFilters"],
                "identitySourceOfTruth": "AGS",
                "unresolvedAdGroup": ags is None,
            }
        )
    return mapping_rows
