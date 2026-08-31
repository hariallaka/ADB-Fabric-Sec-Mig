"""Data models shared by the extractor and translator layers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ColumnLineage:
    """Maps a view's output column back to its source column(s)."""

    output_column: str
    source_table: str | None
    source_columns: list[str]
    is_derived: bool
    expression_sql: str


@dataclass
class ColumnMask:
    """A Databricks dynamic-view column mask, e.g.

    ``CASE WHEN is_account_group_member('grp') THEN salary ELSE NULL END AS salary``
    """

    output_column: str
    source_table: str | None
    source_column: str
    ad_group: str
    mask_function: str
    condition_sql: str
    else_value: str | None


@dataclass
class RowFilter:
    """A single top-level (AND-joined) predicate from a view's WHERE clause."""

    predicate_sql: str
    referenced_columns: list[str]
    referenced_ad_groups: list[str]
    filter_type: str  # GROUP_GATE | GROUP_ATTRIBUTE | USER_MATCH | ATTRIBUTE_MATCH | UNSUPPORTED
    # populated only for filter_type == GROUP_ATTRIBUTE, mapping ad_group -> the
    # data predicate that applies to members of that group, e.g. {"region_us": "region = 'US'"}
    group_predicates: dict[str, str] = field(default_factory=dict)


@dataclass
class ViewSecurityDefinition:
    """Full extraction result for a single Databricks view."""

    catalog: str
    schema: str
    view_name: str
    raw_sql: str
    base_tables: list[str]
    column_lineage: list[ColumnLineage]
    column_masks: list[ColumnMask]
    row_filters: list[RowFilter]
    derived_columns: list[str]
    references_views: list[str]
    is_complex: bool
    unsupported_constructs: list[str]

    @property
    def fq_name(self) -> str:
        return f"{self.catalog}.{self.schema}.{self.view_name}"
