"""Parses Databricks (Unity Catalog) ``CREATE VIEW`` DDL to work out what
data each view exposes:

* the physical source columns referenced anywhere in the SELECT list
  (direct pass-throughs and the columns feeding derived expressions --
  e.g. ``a * b AS c`` contributes ``a`` and ``b``, never ``c``), and which
  physical base table each one actually came from
* the FROM/JOIN clause and WHERE clause, kept verbatim so a "reformatted"
  select (flattened columns, same FROM, same WHERE) can be reconstructed
  for RLS -- the WHERE clause is never decomposed, so OR/AND/NOT structure
  is preserved exactly as written.

Who is *allowed* to see that data is not derived from the SQL at all --
it comes from Unity Catalog's actual SELECT grants on the view, attached
separately via ``grantees`` (see ``extractor/grants.py`` and
``extractor/databricks_client.py``).

Column-to-table attribution for a join: a column the SQL itself qualifies
(``t1.a``) is resolved directly via the FROM/JOIN alias map. An unqualified
column in a *single*-table view is trivially that table's. An unqualified
column in a *multi*-table view needs each candidate table's real column
list to resolve safely (see ``table_columns`` below) -- Databricks/Spark
SQL refuses to ``CREATE VIEW`` in the first place if such a reference is
genuinely ambiguous, so once the tables' schemas are known, resolution is
deterministic, not a guess. Without that schema info, this falls back to
the first base table (alphabetically) exactly as before, but now says so
explicitly in ``unsupported_constructs`` instead of resolving silently.
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


def _table_fq_name(t: exp.Table) -> str:
    return ".".join(p for p in (t.catalog, t.db, t.name) if p)


def _table_alias_map(select: exp.Select) -> dict[str, str]:
    """Maps every alias (and, as a fallback, every bare table name) appearing
    in the FROM/JOIN clause to its fully-qualified table name, so a qualified
    column reference (``t1.a`` or ``orders.amount``) resolves directly.
    """
    mapping: dict[str, str] = {}
    for t in select.find_all(exp.Table):
        fq = _table_fq_name(t)
        if not fq:
            continue
        if t.alias:
            mapping[t.alias] = fq
        mapping.setdefault(t.name, fq)
    return mapping


def _resolve_select_columns(
    select: exp.Select,
    base_tables: list[str],
    table_columns: dict[str, list[str]] | None,
) -> tuple[list[str], list[str], dict[str, str], list[str]]:
    """Returns ``(select_columns, derived_output_columns, column_source_tables,
    unsupported_notes)``.
    """
    alias_map = _table_alias_map(select)

    select_columns: list[str] = []
    derived_output_columns: list[str] = []
    qualified_table_by_column: dict[str, str] = {}
    seen: set[str] = set()

    for proj in select.expressions:
        if isinstance(proj, exp.Star):
            continue
        inner = proj.this if isinstance(proj, exp.Alias) else proj
        if not _is_plain_column(inner):
            derived_output_columns.append(proj.alias_or_name)
        for col in inner.find_all(exp.Column):
            name = col.name
            if name not in seen:
                seen.add(name)
                select_columns.append(name)
            if col.table:
                resolved = alias_map.get(col.table)
                if resolved:
                    qualified_table_by_column.setdefault(name, resolved)

    column_source_tables: dict[str, str] = {}
    unsupported_notes: list[str] = []
    fallback_table = base_tables[0] if base_tables else ""

    for name in select_columns:
        if name in qualified_table_by_column:
            column_source_tables[name] = qualified_table_by_column[name]
        elif len(base_tables) <= 1:
            column_source_tables[name] = fallback_table
        else:
            candidates = (
                [t for t in base_tables if name in (table_columns or {}).get(t, [])]
                if table_columns is not None
                else None
            )
            if candidates is not None and len(candidates) == 1:
                column_source_tables[name] = candidates[0]
            else:
                column_source_tables[name] = fallback_table
                if candidates is None:
                    unsupported_notes.append(
                        f"Column '{name}' is unqualified in a multi-table view; no "
                        f"table-columns schema was supplied to resolve it, so it was "
                        f"attributed to '{fallback_table}' as an unverified fallback -- "
                        f"supply table_columns (live: DatabricksApiClient.fetch_table_columns, "
                        f"offline: --table-columns) or qualify the column in the view."
                    )
                elif len(candidates) == 0:
                    unsupported_notes.append(
                        f"Column '{name}' is unqualified and was not found in any of this "
                        f"view's base tables' known columns {base_tables}; attributed to "
                        f"'{fallback_table}' as an unverified fallback -- verify manually "
                        f"(the supplied table-columns schema may be incomplete)."
                    )
                else:
                    unsupported_notes.append(
                        f"Column '{name}' is unqualified and ambiguous -- it exists in "
                        f"multiple base tables {candidates}; attributed to '{fallback_table}' "
                        f"as an unverified fallback -- verify manually and qualify the column "
                        f"in the view to resolve permanently."
                    )

    return select_columns, derived_output_columns, column_source_tables, unsupported_notes


def parse_view(
    sql_text: str,
    known_view_names: set[str] | None = None,
    grantees: list[str] | None = None,
    table_columns: dict[str, list[str]] | None = None,
) -> ViewDefinition:
    """Parses a single ``CREATE [OR REPLACE] VIEW ... AS SELECT ...`` statement.

    ``table_columns`` (optional) maps a base table's fully-qualified name to
    its real column list, used only to resolve an unqualified column
    reference in a multi-table (joined) view to the correct source table --
    see the module docstring.
    """

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

    base_tables = sorted({_table_fq_name(t) for t in select.find_all(exp.Table)} - {""})
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
            "represent the view and should be manually reviewed. Note: "
            "column-to-table attribution for a JOIN is handled separately "
            "(see any 'unqualified'/'ambiguous' notes below) -- this warning "
            "is about GROUP BY/window/subquery/UNION and about row-filter "
            "attribution for a multi-table WHERE clause, which is not."
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

    select_columns, derived_output_columns, column_source_tables, column_notes = (
        _resolve_select_columns(select, base_tables, table_columns)
    )
    unsupported.extend(column_notes)

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
        column_source_tables=column_source_tables,
        derived_output_columns=derived_output_columns,
        references_views=referenced_views,
        is_complex=is_complex,
        unsupported_constructs=unsupported,
        grantees=grantees or [],
    )


def parse_views_file(
    path: str,
    grants_by_view: dict[str, list[str]] | None = None,
    table_columns: dict[str, list[str]] | None = None,
) -> list[ViewDefinition]:
    """Parses a ``.sql`` file containing one or more ``CREATE VIEW`` statements.

    ``grants_by_view`` maps a view's fully-qualified name (as it appears in
    the ``CREATE VIEW`` statement, e.g. ``sec.hr.v_employee``) to the list of
    principals holding SELECT on it -- see ``extractor/grants.py``.
    ``table_columns`` is passed through to ``parse_view`` for every
    statement -- see its docstring.
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
        view = parse_view(stmt, known_view_names=view_names, table_columns=table_columns)
        view.grantees = grants_by_view.get(view.fq_name, [])
        views.append(view)
    return views


def distinct_base_tables(views: list[ViewDefinition]) -> list[str]:
    """Every distinct physical base table referenced across ``views`` --
    convenience for callers deciding which tables' columns to fetch via
    ``DatabricksApiClient.fetch_table_columns`` before a second parse pass
    (see ``cli.cmd_extract_databricks``).
    """
    return sorted({t for v in views for t in v.base_tables})
