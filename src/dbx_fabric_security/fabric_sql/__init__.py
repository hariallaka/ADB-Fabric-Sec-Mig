"""Fabric SQL analytics endpoint path: re-creates each Databricks view as a
T-SQL view over the Unity Catalog mirrored item, builds a combined
"super business admin" view per base table, and grants SELECT on those
views to Fabric database roles via an AD group -> Fabric role mapping CSV.

This is an alternative to the OneLake data-access-role path in
``translator/role_builder.py``: access is granted per *view*, so two views
over the same table with different column lists and different WHERE
clauses keep their exact Databricks semantics instead of being merged into
one table-level RLS + CLS role. See ``docs/fabric-sql-endpoint-views.md``.
"""

from dbx_fabric_security.fabric_sql.admin_views import AdminExclusion, AdminView, build_admin_views
from dbx_fabric_security.fabric_sql.grants import RolePlan, build_role_plan, parse_role_mapping_csv
from dbx_fabric_security.fabric_sql.script import build_fabric_sql_outputs
from dbx_fabric_security.fabric_sql.state import (
    CatalogDiff,
    build_state,
    diff_states,
    load_state,
    render_revoke_script,
)
from dbx_fabric_security.fabric_sql.views import FabricViewScript, translate_views

__all__ = [
    "AdminExclusion",
    "AdminView",
    "build_admin_views",
    "RolePlan",
    "build_role_plan",
    "parse_role_mapping_csv",
    "build_fabric_sql_outputs",
    "CatalogDiff",
    "build_state",
    "diff_states",
    "load_state",
    "render_revoke_script",
    "FabricViewScript",
    "translate_views",
]
