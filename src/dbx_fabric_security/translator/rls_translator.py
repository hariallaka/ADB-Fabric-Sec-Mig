"""Translates extracted view definitions into a flat RLS entitlement model.

Every principal granted SELECT on a view gets the view's WHERE clause as
its row filter, carried through **verbatim** -- it is never decomposed or
rewritten, so any AND/OR/NOT structure in the original predicate (including
multiple OR-ed conditions) is reproduced exactly. A view with no WHERE
clause gets an unrestricted (``TRUE``) row filter.
"""

from __future__ import annotations

from dataclasses import dataclass

from dbx_fabric_security.extractor.models import ViewDefinition


@dataclass
class RlsEntitlement:
    view: str
    table: str | None
    principal: str
    row_filter_predicate: str
    reformatted_select_sql: str

    def as_dict(self) -> dict:
        return {
            "view": self.view,
            "table": self.table,
            "principal": self.principal,
            "rowFilterPredicate": self.row_filter_predicate,
            "reformattedSelectSql": self.reformatted_select_sql,
        }


def translate_rls(views: list[ViewDefinition]) -> list[RlsEntitlement]:
    entitlements: list[RlsEntitlement] = []

    for view in views:
        if not view.grantees:
            continue
        table = view.base_tables[0] if view.base_tables else None
        predicate = view.where_clause_sql or "TRUE"
        for principal in view.grantees:
            entitlements.append(
                RlsEntitlement(
                    view=view.fq_name,
                    table=table,
                    principal=principal,
                    row_filter_predicate=predicate,
                    reformatted_select_sql=view.reformatted_select_sql,
                )
            )

    return entitlements
