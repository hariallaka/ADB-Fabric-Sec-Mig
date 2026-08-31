"""Parses Databricks (Unity Catalog) ``CREATE VIEW`` DDL and extracts the
security-relevant constructs embedded in it:

* column lineage (which source column(s) feed each output column, and
  whether the output column is *derived* -- e.g. ``a * b AS c``)
* column masks (dynamic-view CLS pattern built on
  ``is_account_group_member`` / ``is_member``)
* row filters (WHERE-clause predicates, including group-gated and
  group-to-attribute predicates)

The parser is intentionally conservative: anything it cannot confidently
classify is captured in ``unsupported_constructs`` rather than silently
dropped or mis-translated, per the spike's limitation-analysis scope.
"""

from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

from dbx_fabric_security.extractor.models import (
    ColumnLineage,
    ColumnMask,
    RowFilter,
    ViewSecurityDefinition,
)

# Function names Databricks/Unity Catalog uses to express identity checks
# inside dynamic views and native row-filter/column-mask functions.
GROUP_MEMBERSHIP_FUNCTIONS = {"is_account_group_member", "is_member"}
USER_FUNCTIONS = {"current_user", "session_user"}

_DIALECT = "databricks"


def _func_name(node: exp.Expression) -> str | None:
    if isinstance(node, exp.Anonymous):
        return str(node.this).lower()
    if isinstance(node, exp.Func):
        return node.sql_name().lower()
    return None


def _find_calls(node: exp.Expression, names: set[str]) -> list[exp.Expression]:
    return [
        f
        for f in node.find_all((exp.Anonymous, exp.Func))
        if _func_name(f) in names
    ]


def _string_arg(func_call: exp.Expression) -> str | None:
    args = func_call.expressions if hasattr(func_call, "expressions") else []
    for a in args:
        if isinstance(a, exp.Literal) and a.is_string:
            return a.this
    return None


def _flatten_and(node: exp.Expression) -> list[exp.Expression]:
    if isinstance(node, exp.And):
        return _flatten_and(node.left) + _flatten_and(node.right)
    return [node]


def _column_names(node: exp.Expression) -> list[str]:
    seen: list[str] = []
    for c in node.find_all(exp.Column):
        name = c.name
        if name and name not in seen:
            seen.append(name)
    return seen


def _classify_case_mask(alias_expr: exp.Alias) -> ColumnMask | None:
    """Detects the dynamic-view CLS pattern:

    ``CASE WHEN is_account_group_member('g') THEN col ELSE <redact> END AS col``
    """
    inner = alias_expr.this
    if not isinstance(inner, exp.Case) or inner.this is not None:
        return None  # only handle searched CASE (no CASE <expr> WHEN form)

    ifs = inner.args.get("ifs") or []
    if len(ifs) != 1:
        return None  # multi-branch CASE is a row-filter pattern, not a simple mask

    branch = ifs[0]
    calls = _find_calls(branch.this, GROUP_MEMBERSHIP_FUNCTIONS)
    if len(calls) != 1:
        return None

    then_val = branch.args.get("true")
    if not isinstance(then_val, exp.Column):
        return None  # the permitted branch must be a bare source column

    default = inner.args.get("default")
    group = _string_arg(calls[0])
    if group is None:
        return None

    return ColumnMask(
        output_column=alias_expr.alias_or_name,
        source_table=then_val.table or None,
        source_column=then_val.name,
        ad_group=group,
        mask_function=_func_name(calls[0]) or "is_account_group_member",
        condition_sql=inner.sql(dialect=_DIALECT),
        else_value=default.sql(dialect=_DIALECT) if default is not None else None,
    )


def _lineage_for_projection(select_expr: exp.Expression) -> ColumnLineage:
    alias = select_expr.alias_or_name
    inner = select_expr.this if isinstance(select_expr, exp.Alias) else select_expr

    source_cols = _column_names(inner)
    is_plain_column = isinstance(inner, exp.Column)
    is_cast_of_column = isinstance(inner, exp.Cast) and isinstance(
        inner.this, exp.Column
    )
    is_derived = not (is_plain_column or is_cast_of_column) and not isinstance(
        inner, exp.Case
    )

    src_table = None
    if isinstance(inner, exp.Column):
        src_table = inner.table or None
    elif is_cast_of_column:
        src_table = inner.this.table or None

    return ColumnLineage(
        output_column=alias,
        source_table=src_table,
        source_columns=source_cols,
        is_derived=is_derived,
        expression_sql=inner.sql(dialect=_DIALECT),
    )


def _classify_row_filter(predicate: exp.Expression) -> RowFilter:
    cols = _column_names(predicate)
    group_calls = _find_calls(predicate, GROUP_MEMBERSHIP_FUNCTIONS)
    user_calls = _find_calls(predicate, USER_FUNCTIONS)
    groups = sorted({g for g in (_string_arg(c) for c in group_calls) if g})
    sql = predicate.sql(dialect=_DIALECT)

    # Pattern 1: bare group gate, e.g. WHERE is_account_group_member('g')
    if isinstance(predicate, (exp.Anonymous, exp.Func)) and groups:
        return RowFilter(
            predicate_sql=sql,
            referenced_columns=cols,
            referenced_ad_groups=groups,
            filter_type="GROUP_GATE",
            group_predicates={g: "TRUE" for g in groups},
        )

    # Pattern 2: attribute driven by group membership via CASE, e.g.
    # WHERE region = CASE WHEN is_account_group_member('us') THEN 'US' ... END
    if isinstance(predicate, exp.EQ):
        left, right = predicate.left, predicate.right
        case_side = right if isinstance(right, exp.Case) else (
            left if isinstance(left, exp.Case) else None
        )
        attr_side = left if case_side is right else right
        if case_side is not None and isinstance(attr_side, exp.Column):
            group_preds: dict[str, str] = {}
            ok = True
            for branch in case_side.args.get("ifs") or []:
                calls = _find_calls(branch.this, GROUP_MEMBERSHIP_FUNCTIONS)
                if len(calls) != 1:
                    ok = False
                    break
                grp = _string_arg(calls[0])
                then_val = branch.args.get("true")
                if grp is None or then_val is None:
                    ok = False
                    break
                group_preds[grp] = f"{attr_side.sql(dialect=_DIALECT)} = {then_val.sql(dialect=_DIALECT)}"
            if ok and group_preds:
                return RowFilter(
                    predicate_sql=sql,
                    referenced_columns=cols,
                    referenced_ad_groups=sorted(group_preds.keys()),
                    filter_type="GROUP_ATTRIBUTE",
                    group_predicates=group_preds,
                )

    # Pattern 3: user-identity match, e.g. WHERE owner_email = current_user()
    if user_calls:
        return RowFilter(
            predicate_sql=sql,
            referenced_columns=cols,
            referenced_ad_groups=[],
            filter_type="USER_MATCH",
        )

    # Pattern 4: plain attribute predicate with no identity function at all --
    # still captured as a row filter candidate (e.g. `is_active = true`) but
    # cannot be tied to a specific AD group automatically.
    if not groups and not user_calls:
        return RowFilter(
            predicate_sql=sql,
            referenced_columns=cols,
            referenced_ad_groups=[],
            filter_type="ATTRIBUTE_MATCH",
        )

    return RowFilter(
        predicate_sql=sql,
        referenced_columns=cols,
        referenced_ad_groups=groups,
        filter_type="UNSUPPORTED",
    )


def parse_view(sql_text: str, known_view_names: set[str] | None = None) -> ViewSecurityDefinition:
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
            "lineage and predicate extraction may be incomplete and should be "
            "manually reviewed before translation."
        )
    if referenced_views:
        unsupported.append(
            f"View is built on nested view(s) {referenced_views}; security "
            "definitions on the base view(s) must be resolved and composed "
            "before translation (see limitations doc)."
        )

    lineage: list[ColumnLineage] = []
    masks: list[ColumnMask] = []
    derived_columns: list[str] = []

    star_projection = any(isinstance(p, exp.Star) for p in select.expressions)
    if star_projection:
        unsupported.append(
            "View uses SELECT *; explicit column list is required to extract "
            "column-level lineage/CLS. Expand the view definition or supply the "
            "resolved column list out of band."
        )

    for proj in select.expressions:
        if isinstance(proj, exp.Star):
            continue
        mask = None
        if isinstance(proj, exp.Alias):
            mask = _classify_case_mask(proj)
        if mask is not None:
            masks.append(mask)
            lineage.append(
                ColumnLineage(
                    output_column=mask.output_column,
                    source_table=mask.source_table,
                    source_columns=[mask.source_column],
                    is_derived=False,
                    expression_sql=mask.condition_sql,
                )
            )
            continue

        line = _lineage_for_projection(proj)
        lineage.append(line)
        if line.is_derived:
            derived_columns.append(line.output_column)

    row_filters: list[RowFilter] = []
    where = select.args.get("where")
    if where is not None:
        for pred in _flatten_and(where.this):
            rf = _classify_row_filter(pred)
            row_filters.append(rf)
            if rf.filter_type == "UNSUPPORTED":
                unsupported.append(
                    f"Row filter predicate could not be classified and requires "
                    f"manual translation: {rf.predicate_sql}"
                )

    return ViewSecurityDefinition(
        catalog=catalog,
        schema=schema,
        view_name=view_name,
        raw_sql=sql_text.strip(),
        base_tables=base_tables,
        column_lineage=lineage,
        column_masks=masks,
        row_filters=row_filters,
        derived_columns=derived_columns,
        references_views=referenced_views,
        is_complex=is_complex,
        unsupported_constructs=unsupported,
    )


def parse_views_file(path: str) -> list[ViewSecurityDefinition]:
    """Parses a ``.sql`` file containing one or more ``CREATE VIEW`` statements."""

    with open(path, encoding="utf-8") as fh:
        content = fh.read()

    statements = [s.strip() for s in re.split(r";\s*(?:\n|$)", content) if s.strip()]
    view_stmts = [s for s in statements if re.search(r"\bcreate\b.*\bview\b", s, re.I)]
    view_names = set()
    for s in view_stmts:
        m = re.search(r"view\s+([`\"\[]?[\w.]+[`\"\]]?)", s, re.I)
        if m:
            view_names.add(m.group(1).split(".")[-1].strip("`\"[]"))

    return [parse_view(s, known_view_names=view_names) for s in view_stmts]
