"""Translates Databricks ``CREATE VIEW`` DDL into T-SQL ``CREATE OR ALTER
VIEW`` statements for the SQL analytics endpoint of a Fabric mirrored
Unity Catalog item.

Name mapping: one UC catalog = one Fabric mirrored item (= one SQL
analytics endpoint database). A UC reference ``catalog.schema.object``
becomes ``[schema].[object]`` inside that catalog's endpoint. A reference
to a *different* catalog would need that other mirrored item's Fabric name
and is blocked for manual review rather than guessed.

Translation is done by sqlglot (``databricks`` -> ``tsql``), but sqlglot
passes functions it doesn't know straight through and emits some
constructs T-SQL rejects (e.g. a boolean expression in a SELECT list,
``ILIKE``). So a view is only placed in the deployable script when it
contains none of the constructs in ``_BLOCKING_NODE_TYPES`` /
``_IDENTITY_FUNCTIONS`` and no unrecognised function. Anything else goes to
the needs-review output with the reason. This fails closed: a view that
can't be translated with confidence is never deployed and nobody gets a
grant on it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ErrorLevel

from dbx_fabric_security.extractor.models import ViewDefinition

_SOURCE_DIALECT = "databricks"
_TARGET_DIALECT = "tsql"

# Functions whose result depends on *who* is querying. Databricks and
# Fabric resolve identity differently (UC user/group names vs. the Entra
# UPN Fabric sees, and Databricks account groups vs. Fabric database
# roles), so these are never auto-translated.
_IDENTITY_FUNCTIONS = {
    "current_user",
    "session_user",
    "user",
    "is_member",
    "is_account_group_member",
    "current_groups",
}
_IDENTITY_NODE_TYPES = (exp.CurrentUser, exp.SessionUser)

# Constructs sqlglot either passes through unchanged into invalid T-SQL or
# translates with different semantics.
_BLOCKING_NODE_TYPES: dict[type, str] = {
    exp.ILike: "ILIKE (no T-SQL equivalent; rewrite with LOWER(...) LIKE or a case-insensitive collation)",
    exp.RegexpLike: "RLIKE/REGEXP (no T-SQL regex predicate)",
    exp.Explode: "EXPLODE (no T-SQL equivalent; arrays are not mirrored as arrays)",
    exp.Lateral: "LATERAL VIEW",
    exp.Qualify: "QUALIFY (rewrite as a subquery filtering on the window function)",
    exp.JSONExtract: "JSON/variant path extraction (`col:path`)",
    exp.Pivot: "PIVOT/UNPIVOT",
    exp.TableSample: "TABLESAMPLE",
    exp.Bracket: "array/map element access",
    exp.Struct: "STRUCT construction",
    exp.Array: "ARRAY construction",
    exp.Lambda: "higher-order function / lambda",
}

_BOOLEAN_PROJECTION_TYPES = (exp.Predicate, exp.Connector, exp.Not)


@dataclass
class FabricViewScript:
    source_view: str
    catalog: str
    target_schema: str
    target_view: str
    ddl: str | None
    blocking_issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    grantees: list[str] = field(default_factory=list)

    @property
    def deployable(self) -> bool:
        return not self.blocking_issues and self.ddl is not None

    @property
    def target_name(self) -> str:
        return f"{quote_ident(self.target_schema)}.{quote_ident(self.target_view)}"

    def as_dict(self) -> dict:
        return {
            "sourceView": self.source_view,
            "catalog": self.catalog,
            "targetView": self.target_name,
            "status": "deployable" if self.deployable else "needs_review",
            "blockingIssues": self.blocking_issues,
            "warnings": self.warnings,
            "dependsOn": self.depends_on,
            "grantees": self.grantees,
        }


def quote_ident(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def quote_nstring(value: str) -> str:
    return "N'" + value.replace("'", "''") + "'"


def _fq(catalog: str | None, schema: str | None, name: str) -> str:
    return ".".join(p for p in (catalog, schema, name) if p)


def find_blocking_constructs(node: exp.Expression) -> list[str]:
    """Constructs that must not be auto-translated. Used for whole views and
    for individual WHERE clauses (admin views)."""
    issues: list[str] = []
    seen: set[str] = set()

    def add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            issues.append(msg)

    for n in node.walk():
        if isinstance(n, _IDENTITY_NODE_TYPES) or (
            isinstance(n, exp.Anonymous) and str(n.this).lower() in _IDENTITY_FUNCTIONS
        ):
            fname = n.sql(dialect=_SOURCE_DIALECT)
            add(
                f"Identity-based predicate {fname}: Databricks user/group identity does not "
                f"map 1:1 to Fabric (Entra UPN via SUSER_SNAME(), database roles via "
                f"IS_ROLEMEMBER()). Rewrite and test manually."
            )
        elif isinstance(n, exp.Anonymous):
            add(
                f"Function {str(n.this)}() has no verified T-SQL translation "
                f"(sqlglot would pass it through unchanged)."
            )
        else:
            for node_type, label in _BLOCKING_NODE_TYPES.items():
                if isinstance(n, node_type):
                    add(f"Unsupported construct: {label}.")
    return issues


def _boolean_projection_issues(body: exp.Expression) -> list[str]:
    issues = []
    for select in body.find_all(exp.Select):
        for proj in select.expressions:
            inner = proj.this if isinstance(proj, exp.Alias) else proj
            if isinstance(inner, _BOOLEAN_PROJECTION_TYPES):
                issues.append(
                    f"SELECT-list item '{proj.alias_or_name}' is a boolean expression, which "
                    f"T-SQL cannot project; rewrite as CASE WHEN ... THEN 1 ELSE 0 END."
                )
    return issues


def build_case_map(base_tables: list[str], table_columns: dict[str, list[str]] | None) -> dict[str, str]:
    """lower-cased column name -> its real casing, across ``base_tables``.
    A name with conflicting casings across tables is left out (ambiguous)."""
    if not table_columns:
        return {}
    by_lower: dict[str, set[str]] = {}
    for table in base_tables:
        for col in table_columns.get(table, []):
            by_lower.setdefault(col.lower(), set()).add(col)
    return {k: next(iter(v)) for k, v in by_lower.items() if len(v) == 1}


def normalize_column_case(node: exp.Expression, case_map: dict[str, str]) -> list[str]:
    """Rewrites column references in place to the source table's real
    casing. Databricks resolves identifiers case-insensitively; the Fabric
    endpoint's default collation is case-sensitive (*_BIN2), so ``C2`` vs a
    physical column ``c2`` must be fixed before deployment."""
    changes: list[str] = []
    for col in node.find_all(exp.Column):
        actual = case_map.get(col.name.lower())
        if actual and actual != col.name:
            changes.append(f"{col.name}->{actual}")
            col.set("this", exp.to_identifier(actual))
    return sorted(set(changes))


def _view_columns_clause(create: exp.Create) -> str:
    target = create.this
    if isinstance(target, exp.Schema) and target.expressions:
        names = [e.name for e in target.expressions]
        return " (" + ", ".join(quote_ident(n) for n in names) + ")"
    return ""


def translate_view(
    view: ViewDefinition,
    known_views: set[str],
    table_columns: dict[str, list[str]] | None = None,
) -> FabricViewScript:
    """``known_views``: lower-cased fq names of every view in this extract,
    used to record view-on-view dependencies so they can be created in
    order."""
    script = FabricViewScript(
        source_view=view.fq_name,
        catalog=view.catalog,
        target_schema=view.schema,
        target_view=view.view_name,
        ddl=None,
        grantees=list(view.grantees),
    )

    if not view.catalog or not view.schema:
        script.blocking_issues.append(
            "View name is not fully qualified (catalog.schema.view); cannot place it in a "
            "mirrored item's schema."
        )
        return script

    create = sqlglot.parse_one(view.raw_sql, read=_SOURCE_DIALECT)
    body = create.expression
    if body is None:
        script.blocking_issues.append("Could not locate the view body.")
        return script

    script.blocking_issues.extend(find_blocking_constructs(body))
    script.blocking_issues.extend(_boolean_projection_issues(body))

    if isinstance(body, exp.Select) and body.args.get("order") and not body.args.get("limit"):
        script.blocking_issues.append(
            "Top-level ORDER BY without LIMIT is invalid in a T-SQL view; remove it."
        )
    if any(isinstance(p, exp.Star) for s in body.find_all(exp.Select) for p in s.expressions):
        script.warnings.append(
            "SELECT *: T-SQL binds the column list when the view is created. Re-run this "
            "script after the mirrored table's schema changes."
        )

    cte_names = {cte.alias_or_name.lower() for cte in body.find_all(exp.CTE)}
    depends: set[str] = set()
    for table in list(body.find_all(exp.Table)):
        if not table.name:
            continue
        if not table.db:
            if table.name.lower() in cte_names:
                continue
            script.blocking_issues.append(
                f"Unqualified table reference '{table.name}': it would resolve against "
                f"the Fabric default schema (dbo), not the Databricks one. Qualify it."
            )
            continue
        catalog = table.catalog or view.catalog
        if not table.catalog:
            script.warnings.append(
                f"'{table.db}.{table.name}' has no catalog; assumed same catalog '{view.catalog}'."
            )
        if catalog.lower() != view.catalog.lower():
            script.blocking_issues.append(
                f"Cross-catalog reference '{_fq(catalog, table.db, table.name)}': needs that "
                f"catalog's mirrored item name (and cross-item permissions). Rewrite manually."
            )
            continue
        fq = _fq(catalog, table.db, table.name).lower()
        if fq in known_views:
            depends.add(fq)
        table.set("catalog", None)

    script.depends_on = sorted(depends)

    case_map = build_case_map(view.base_tables, table_columns)
    if table_columns is None:
        script.warnings.append(
            "Column casing not verified (no table-columns schema supplied). The Fabric "
            "endpoint's default collation is case-sensitive; supply --table-columns."
        )
    else:
        changes = normalize_column_case(body, case_map)
        if changes:
            script.warnings.append(f"Column casing normalized to source tables: {changes}")

    try:
        body_sql = body.sql(
            dialect=_TARGET_DIALECT, identify=True, pretty=True, unsupported_level=ErrorLevel.RAISE
        )
    except Exception as e:  # sqlglot UnsupportedError and friends
        script.blocking_issues.append(f"sqlglot could not translate to T-SQL: {e}")
        return script

    script.ddl = (
        f"CREATE OR ALTER VIEW {script.target_name}{_view_columns_clause(create)} AS\n{body_sql};"
    )
    return script


def translate_views(
    views: list[ViewDefinition], table_columns: dict[str, list[str]] | None = None
) -> list[FabricViewScript]:
    """Translates every view, blocks a view whose dependency is blocked
    (transitively), and returns them in dependency order (a view after the
    views it selects from)."""
    known = {v.fq_name.lower() for v in views}
    scripts = [translate_view(v, known, table_columns) for v in views]
    by_name = {s.source_view.lower(): s for s in scripts}

    changed = True
    while changed:
        changed = False
        for s in scripts:
            if not s.deployable:
                continue
            for dep in s.depends_on:
                d = by_name.get(dep)
                if d is not None and not d.deployable:
                    s.blocking_issues.append(
                        f"Depends on view '{d.source_view}', which needs review."
                    )
                    changed = True
                    break

    ordered: list[FabricViewScript] = []
    state: dict[str, int] = {}  # 1 = visiting, 2 = done

    def visit(s: FabricViewScript) -> None:
        key = s.source_view.lower()
        if state.get(key) == 2:
            return
        if state.get(key) == 1:
            s.blocking_issues.append("Circular view dependency.")
            return
        state[key] = 1
        for dep in s.depends_on:
            if dep in by_name:
                visit(by_name[dep])
        state[key] = 2
        ordered.append(s)

    for s in sorted(scripts, key=lambda x: x.source_view.lower()):
        visit(s)
    return ordered
