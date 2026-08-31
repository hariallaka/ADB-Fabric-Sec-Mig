"""Parses Databricks (Unity Catalog) ``CREATE VIEW`` DDL to work out what
data each view exposes:

* the physical source columns referenced anywhere in the SELECT list
  (direct pass-throughs and the columns feeding derived expressions --
  e.g. ``a * b AS c`` contributes ``a`` and ``b``, never ``c``)
* the FROM/JOIN clause and WHERE clause, kept verbatim so a "reformatted"
  select (flattened columns, same FROM, same WHERE) can be reconstructed
  for RLS -- the WHERE clause is never decomposed, so OR/AND/NOT structure
  is preserved exactly as written.

Who is *allowed* to see that data is not derived from the SQL at all --
it comes from Unity Catalog's actual SELECT grants on the view, attached
separately via ``grantees`` (see ``extractor/grants.py`` and
``extractor/databricks_client.py``).
"""

from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

from dbx_fabric_security.extractor.models import ViewDefinition

_DIALECT = "databricks"


def _is_plain_column(expr: exp.Expression) -> bool:
    return isinstance(expr, exp.Column) or (
        isinstance(expr, exp.Cast) and isinstance(expr.this, exp.Column)
    )


def parse_view(
    sql_text: str,
    known_view_names: set[str] | None = None,
    grantees: list[str] | None = None,
) -> ViewDefinition:
    """Parses a single ``CREATE [OR REPLACE] VIEW ... AS SELECT ...`` statement."""

    known_view_names = {v.lower() for v in (known_view_names or set())}
    tree = sqlglot.parse_one(sql_text, read=_DIALECT)

    if not isinstance(tree, exp.Create) or tree.args.get("kind", "").upper() != "VIEW":
        raise ValueError("Input SQL is not a CREATE VIEW statement")

    table_ref = tree.this
    catalog = table_ref.catalog or ""
    schema = table_ref.db or ""
    view_name = table_ref.name

    select = tree.find(exp.Select)
    if select is None:
        raise ValueError(f"Could not locate a SELECT body for view {view_name}")

    unsupported: list[str] = []

    base_tables = sorted(
        {
            ".".join(p for p in (t.catalog, t.db, t.name) if p)
            for t in select.find_all(exp.Table)
        }
    )
    referenced_views = sorted(
        t.name.lower()
        for t in select.find_all(exp.Table)
        if t.name.lower() in known_view_names
    )

    is_complex = bool(
        select.args.get("joins")
        or select.args.get("group")
        or select.find(exp.Window)
        or select.find(exp.Subquery)
        or tree.find(exp.Union)
    )
    if is_complex:
        unsupported.append(
            "View contains JOIN/GROUP BY/window/subquery/UNION constructs; "
            "the flattened column list and reformatted SELECT may not fully "
            "represent the view and should be manually reviewed."
        )
    if referenced_views:
        unsupported.append(
            f"View is built on nested view(s) {referenced_views}; that base "
            "view's own SELECT grants are not composed into this view's "
            "translation (see limitations doc)."
        )

    star_projection = any(isinstance(p, exp.Star) for p in select.expressions)
    if star_projection:
        unsupported.append(
            "View uses SELECT *; explicit column list is required to flatten "
            "the physical source columns. Expand the view definition or "
            "supply the resolved column list out of band."
        )

    select_columns: list[str] = []
    derived_output_columns: list[str] = []
    seen: set[str] = set()

    for proj in select.expressions:
        if isinstance(proj, exp.Star):
            continue
        inner = proj.this if isinstance(proj, exp.Alias) else proj
        if not _is_plain_column(inner):
            derived_output_columns.append(proj.alias_or_name)
        for col in inner.find_all(exp.Column):
            if col.name not in seen:
                seen.add(col.name)
                select_columns.append(col.name)

    from_expr = select.find(exp.From)
    from_clause_sql = from_expr.sql(dialect=_DIALECT) if from_expr else ""
    joins = select.args.get("joins") or []
    if joins:
        from_clause_sql += " " + " ".join(j.sql(dialect=_DIALECT) for j in joins)

    where = select.args.get("where")
    where_clause_sql = where.this.sql(dialect=_DIALECT) if where else None

    return ViewDefinition(
        catalog=catalog,
        schema=schema,
        view_name=view_name,
        raw_sql=sql_text.strip(),
        base_tables=base_tables,
        from_clause_sql=from_clause_sql,
        where_clause_sql=where_clause_sql,
        select_columns=select_columns,
        derived_output_columns=derived_output_columns,
        references_views=referenced_views,
        is_complex=is_complex,
        unsupported_constructs=unsupported,
        grantees=grantees or [],
    )


def parse_views_file(
    path: str, grants_by_view: dict[str, list[str]] | None = None
) -> list[ViewDefinition]:
    """Parses a ``.sql`` file containing one or more ``CREATE VIEW`` statements.

    ``grants_by_view`` maps a view's fully-qualified name (as it appears in
    the ``CREATE VIEW`` statement, e.g. ``sec.hr.v_employee``) to the list of
    principals holding SELECT on it -- see ``extractor/grants.py``.
    """

    with open(path, encoding="utf-8") as fh:
        content = fh.read()

    statements = [s.strip() for s in re.split(r";\s*(?:\n|$)", content) if s.strip()]

    # Identify CREATE VIEW statements (and their names) via sqlglot itself,
    # not a text regex -- a regex over raw statement text (including its
    # leading SQL comments) is easily fooled by a comment that happens to
    # contain the word "view" followed by another word.
    view_stmts: list[str] = []
    view_names: set[str] = set()
    for s in statements:
        try:
            tree = sqlglot.parse_one(s, read=_DIALECT)
        except Exception:
            continue
        if isinstance(tree, exp.Create) and tree.args.get("kind", "").upper() == "VIEW":
            view_stmts.append(s)
            view_names.add(tree.this.name.lower())

    grants_by_view = grants_by_view or {}
    views = []
    for stmt in view_stmts:
        view = parse_view(stmt, known_view_names=view_names)
        view.grantees = grants_by_view.get(view.fq_name, [])
        views.append(view)
    return views
