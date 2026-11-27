"""Builds one "super business admin" view per base table: the union of
every column any granted view exposes from that table (CLS), over the OR of
every such view's WHERE clause (RLS).

This is a deliberate over-grant for the admin role only. For views

    v1: SELECT c1, c2, c3 FROM t1 WHERE c1 > 2
    v2: SELECT c4, c5, c6 FROM t1 WHERE c2 < 4

the admin view is

    SELECT c1, c2, c3, c4, c5, c6 FROM t1 WHERE (c1 > 2) OR (c2 < 4)

so the admin sees c4..c6 on rows where only c1 > 2 holds, which no
ordinary grantee can. A view with no WHERE clause contributes every row of
the table.

Only views that are safe to fold into a single-table predicate are
included. Every other view is listed in ``AdminExclusion`` with the reason:
multi-table/aggregate views, views on views, views whose translation needs
review, and views with no grantee. An exclusion means the admin gets
*less*, never more, than the union.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from dbx_fabric_security.extractor.models import ViewDefinition
from dbx_fabric_security.fabric_sql.views import (
    FabricViewScript,
    build_case_map,
    find_blocking_constructs,
    normalize_column_case,
    quote_ident,
)

_SOURCE_DIALECT = "databricks"
_TARGET_DIALECT = "tsql"


@dataclass
class AdminView:
    base_table: str
    catalog: str
    target_schema: str
    target_view: str
    columns: list[str]
    predicates: list[str]  # T-SQL; empty list = no row filter (all rows)
    source_views: list[str]
    warnings: list[str] = field(default_factory=list)

    @property
    def target_name(self) -> str:
        return f"{quote_ident(self.target_schema)}.{quote_ident(self.target_view)}"

    @property
    def ddl(self) -> str:
        _, schema, table = self.base_table.split(".")
        cols = ",\n  ".join(quote_ident(c) for c in self.columns)
        sql = (
            f"CREATE OR ALTER VIEW {self.target_name} AS\n"
            f"SELECT\n  {cols}\nFROM {quote_ident(schema)}.{quote_ident(table)}"
        )
        if self.predicates:
            sql += "\nWHERE\n  " + "\n  OR ".join(f"({p})" for p in self.predicates)
        return sql + ";"

    def as_dict(self) -> dict:
        return {
            "baseTable": self.base_table,
            "targetView": self.target_name,
            "columns": self.columns,
            "rowFilter": " OR ".join(f"({p})" for p in self.predicates) or "TRUE (all rows)",
            "sourceViews": self.source_views,
            "warnings": self.warnings,
        }


@dataclass
class AdminExclusion:
    source_view: str
    reason: str

    def as_dict(self) -> dict:
        return {"sourceView": self.source_view, "reason": self.reason}


def _exclusion_reason(view: ViewDefinition, script: FabricViewScript | None) -> str | None:
    if not view.grantees:
        return "No SELECT grantee in Unity Catalog; not part of anyone's access."
    if script is not None and not script.deployable:
        return "View needs review (see its blocking issues); not folded into the admin view."
    if view.references_views:
        return (
            f"Built on view(s) {view.references_views}; not folded in. The admin view covers "
            f"this data only if the base view is itself granted and folded in."
        )
    if view.is_complex or len(view.base_tables) != 1:
        return "Multi-table, aggregate, window, subquery or UNION view; its WHERE clause can't be applied to one table."
    if len(view.base_tables[0].split(".")) != 3:
        return "Base table is not fully qualified (catalog.schema.table)."
    return None


def _where_predicate(view: ViewDefinition) -> exp.Expression | None:
    create = sqlglot.parse_one(view.raw_sql, read=_SOURCE_DIALECT)
    select = create.expression
    where = select.args.get("where") if isinstance(select, exp.Select) else None
    if where is None:
        return None
    predicate = where.this.copy()
    # Single-table view: drop alias/table qualifiers (o.active -> active) so
    # the predicate binds to the admin view's FROM.
    for col in predicate.find_all(exp.Column):
        col.set("table", None)
        col.set("db", None)
        col.set("catalog", None)
    return predicate


def build_admin_views(
    views: list[ViewDefinition],
    scripts: list[FabricViewScript],
    admin_schema: str,
    table_columns: dict[str, list[str]] | None = None,
) -> tuple[list[AdminView], list[AdminExclusion]]:
    script_by_view = {s.source_view: s for s in scripts}
    exclusions: list[AdminExclusion] = []
    per_table: dict[str, dict] = {}

    for view in sorted(views, key=lambda v: v.fq_name):
        reason = _exclusion_reason(view, script_by_view.get(view.fq_name))
        if reason:
            exclusions.append(AdminExclusion(view.fq_name, reason))
            continue

        table = view.base_tables[0]
        case_map = build_case_map([table], table_columns)

        columns = list(view.select_columns)
        if any(isinstance(p, exp.Star) for p in sqlglot.parse_one(view.raw_sql, read=_SOURCE_DIALECT).expression.expressions):
            if table_columns and table in table_columns:
                columns = list(table_columns[table])
            else:
                exclusions.append(AdminExclusion(
                    view.fq_name,
                    "SELECT * and no table-columns schema for its base table; column set unknown.",
                ))
                continue
        columns = [case_map.get(c.lower(), c) for c in columns]

        predicate = _where_predicate(view)
        predicate_sql = None
        if predicate is not None:
            issues = find_blocking_constructs(predicate)
            if issues:
                exclusions.append(AdminExclusion(view.fq_name, "; ".join(issues)))
                continue
            normalize_column_case(predicate, case_map)
            predicate_sql = predicate.sql(dialect=_TARGET_DIALECT, identify=True)

        entry = per_table.setdefault(
            table, {"columns": [], "predicates": [], "all_rows": False, "views": []}
        )
        for c in columns:
            if c not in entry["columns"]:
                entry["columns"].append(c)
        if predicate_sql is None:
            entry["all_rows"] = True
        elif predicate_sql not in entry["predicates"]:
            entry["predicates"].append(predicate_sql)
        entry["views"].append(view.fq_name)

    admin_views: list[AdminView] = []
    names_seen: dict[tuple[str, str], str] = {}
    for table, entry in sorted(per_table.items()):
        catalog, schema, name = table.split(".")
        view_name = f"{schema}__{name}"
        key = (catalog.lower(), view_name.lower())
        if key in names_seen:
            raise ValueError(
                f"Admin view name collision: {table} and {names_seen[key]} both map to "
                f"[{admin_schema}].[{view_name}]"
            )
        names_seen[key] = table
        warnings = []
        if entry["all_rows"] and entry["predicates"]:
            warnings.append(
                "At least one source view has no WHERE clause, so the admin view returns all rows."
            )
        admin_views.append(
            AdminView(
                base_table=table,
                catalog=catalog,
                target_schema=admin_schema,
                target_view=view_name,
                columns=entry["columns"],
                predicates=[] if entry["all_rows"] else entry["predicates"],
                source_views=entry["views"],
                warnings=warnings,
            )
        )
    return admin_views, exclusions
