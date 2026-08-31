"""Loads Unity Catalog SELECT grants on views from a local CSV -- the
offline/test counterpart to ``DatabricksApiClient.fetch_view_grants`` +
``fetch_principal_directory``.

CSV columns: ``view`` (fully-qualified, e.g. ``sec.hr.v_employee``),
``principal`` (AD group name or user id), ``principal_object_id`` (the
Azure AD object id for that group/user -- optional, leave blank if
unknown), ``privilege``. Only ``SELECT`` rows are used; a view is never
granted access as a side effect of parsing its SQL -- grants only ever come
from this file or the live Databricks query.
"""

from __future__ import annotations

import csv


def parse_grants_csv(path: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Returns ``(grants_by_view, principal_directory)``:
    ``grants_by_view`` maps a view's fully-qualified name to the list of
    principal names holding SELECT on it; ``principal_directory`` maps a
    principal name to its Azure AD object id, for every row where one was
    supplied.
    """
    grants_by_view: dict[str, list[str]] = {}
    principal_directory: dict[str, str] = {}

    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["privilege"].strip().upper() != "SELECT":
                continue
            view = row["view"].strip()
            principal = row["principal"].strip()
            object_id = (row.get("principal_object_id") or "").strip()

            grants_by_view.setdefault(view, [])
            if principal not in grants_by_view[view]:
                grants_by_view[view].append(principal)
            if object_id:
                principal_directory[principal] = object_id

    return grants_by_view, principal_directory
