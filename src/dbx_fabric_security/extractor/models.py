"""Data model shared by the extractor and translator layers.

Security is driven entirely by who actually holds ``SELECT`` on a view in
Unity Catalog (``grantees``) -- not by parsing masking/filter logic out of
the view's SQL text. The view's SQL is only used to work out *what data*
that grant covers: which physical source columns it exposes (CLS) and what
row predicate it applies (RLS).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ViewDefinition:
    catalog: str
    schema: str
    view_name: str
    raw_sql: str
    base_tables: list[str]
    from_clause_sql: str
    where_clause_sql: str | None
    # Physical source columns referenced anywhere in the SELECT list --
    # direct pass-throughs and the columns feeding derived expressions --
    # in first-seen order, with derived output aliases themselves excluded.
    select_columns: list[str]
    # Which physical base table each entry in select_columns actually came
    # from -- trivial for a single-table view, resolved via the FROM/JOIN
    # alias map for a column the SQL itself qualifies (e.g. t1.a), and via
    # an optional live table-columns lookup for an unqualified column in a
    # multi-table view. Always populated (falls back to base_tables[0] with
    # an unsupported_constructs entry when it can't be resolved safely --
    # see view_parser.py and README "Column-to-table attribution").
    column_source_tables: dict[str, str]
    derived_output_columns: list[str]
    references_views: list[str]
    is_complex: bool
    unsupported_constructs: list[str]
    # Principals (AD groups or users) holding SELECT on this view in Unity
    # Catalog. Populated by the extraction step, not inferred from SQL.
    grantees: list[str] = field(default_factory=list)

    @property
    def fq_name(self) -> str:
        return f"{self.catalog}.{self.schema}.{self.view_name}"

    @property
    def reformatted_select_sql(self) -> str:
        """The view's SELECT reformatted per the RLS translation rule:
        derived expressions replaced by their flattened source columns,
        WHERE clause carried through verbatim (including any OR/AND/NOT
        structure -- it is never decomposed).
        """
        cols = ", ".join(self.select_columns) if self.select_columns else "*"
        sql = f"SELECT {cols} {self.from_clause_sql}"
        if self.where_clause_sql:
            sql += f" WHERE {self.where_clause_sql}"
        return sql
