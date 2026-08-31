"""Loads Unity Catalog SELECT grants on views from a local CSV -- the
offline/test counterpart to ``DatabricksApiClient.fetch_view_grants``.

CSV columns: ``view`` (fully-qualified, e.g. ``sec.hr.v_employee``),
``principal`` (AD group name or user id), ``privilege``. Only ``SELECT``
rows are used; a view is never granted access as a side effect of parsing
its SQL -- grants only ever come from this file or the live Databricks
query.
"""

from __future__ import annotations

import csv


def parse_grants_csv(path: str) -> dict[str, list[str]]:
    grants_by_view: dict[str, list[str]] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["privilege"].strip().upper() != "SELECT":
                continue
            view = row["view"].strip()
            principal = row["principal"].strip()
            grants_by_view.setdefault(view, [])
            if principal not in grants_by_view[view]:
                grants_by_view[view].append(principal)
    return grants_by_view
