"""Translates extracted view definitions into a flat CLS entitlement model.

The rule is simple: every principal granted SELECT on a view gets a CLS
PERMIT entitlement on every physical column that view's SELECT list
references -- whether the column is selected directly or feeds a derived
expression. A derived output column itself (e.g. ``c`` in ``a * b AS c``)
never gets an entitlement, since it isn't a physical column to secure; its
source columns (``a``, ``b``) do.

Each entitlement's ``table`` comes from the view's own per-column
attribution (``ViewDefinition.column_source_tables``), not a single table
for the whole view -- for a joined view, different columns can and do come
from different base tables, and this reflects that instead of attributing
everything to one table (see ``extractor/view_parser.py``).
"""

from __future__ import annotations

from dataclasses import dataclass

from dbx_fabric_security.extractor.models import ViewDefinition


@dataclass
class ClsEntitlement:
    view: str
    table: str | None
    column: str
    principal: str

    def as_dict(self) -> dict:
        return {
            "view": self.view,
            "table": self.table,
            "column": self.column,
            "principal": self.principal,
        }


def translate_cls(views: list[ViewDefinition]) -> list[ClsEntitlement]:
    entitlements: list[ClsEntitlement] = []

    for view in views:
        if not view.grantees or not view.select_columns:
            continue
        fallback_table = view.base_tables[0] if view.base_tables else None
        for principal in view.grantees:
            for column in view.select_columns:
                table = view.column_source_tables.get(column, fallback_table)
                entitlements.append(
                    ClsEntitlement(view=view.fq_name, table=table, column=column, principal=principal)
                )

    return entitlements
