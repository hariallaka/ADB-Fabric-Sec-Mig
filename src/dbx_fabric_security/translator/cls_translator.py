"""Translates extracted Databricks CLS constructs into a flat, Fabric-ready
column-security entitlement model.

Per the spike's key design assumption, a *derived* output column (e.g.
``a * b AS c``) never receives a direct entitlement of its own. Instead the
source columns it was computed from (``a``, ``b``) are surfaced as
entitlement candidates, tagged ``DERIVED_SOURCE`` so the lineage back to the
derived column stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dbx_fabric_security.extractor.models import ViewSecurityDefinition


@dataclass
class ClsEntitlement:
    view: str
    table: str | None
    column: str
    ad_group: str | None
    access_effect: str  # PERMIT | DEFAULT_VISIBLE
    source_type: str  # DIRECT | MASKED | DERIVED_SOURCE
    derived_output_column: str | None = None
    mask_else_value: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "view": self.view,
            "table": self.table,
            "column": self.column,
            "adGroup": self.ad_group,
            "accessEffect": self.access_effect,
            "sourceType": self.source_type,
            "derivedOutputColumn": self.derived_output_column,
            "maskElseValue": self.mask_else_value,
            "notes": self.notes,
        }


def translate_cls(views: list[ViewSecurityDefinition]) -> list[ClsEntitlement]:
    entitlements: list[ClsEntitlement] = []

    for view in views:
        derived_lookup = {
            lin.output_column: lin for lin in view.column_lineage if lin.is_derived
        }

        # 1. Explicit masks -> PERMIT entitlement for the mapped AD group.
        for mask in view.column_masks:
            entitlements.append(
                ClsEntitlement(
                    view=view.fq_name,
                    table=mask.source_table or _primary_base_table(view),
                    column=mask.source_column,
                    ad_group=mask.ad_group,
                    access_effect="PERMIT",
                    source_type="MASKED",
                    mask_else_value=mask.else_value,
                )
            )

        # 2. Derived columns: no entitlement for the derived output column
        #    itself; source columns feeding it become entitlement candidates
        #    without an AD group (no group was expressed for them in the
        #    view -- they inherit whatever grant applies to the base table
        #    unless a separate mask/grant exists), so they're flagged for
        #    governance review rather than auto-permitted.
        for out_col, lineage in derived_lookup.items():
            for src_col in lineage.source_columns:
                already_masked = any(
                    m.source_column == src_col for m in view.column_masks
                )
                if already_masked:
                    continue
                entitlements.append(
                    ClsEntitlement(
                        view=view.fq_name,
                        table=lineage.source_table or _primary_base_table(view),
                        column=src_col,
                        ad_group=None,
                        access_effect="DEFAULT_VISIBLE",
                        source_type="DERIVED_SOURCE",
                        derived_output_column=out_col,
                        notes=[
                            f"Column '{src_col}' feeds derived output column "
                            f"'{out_col}' ({lineage.expression_sql}). No CLS "
                            "entitlement is generated for the derived column "
                            "itself; verify whether an explicit grant is "
                            "required for the source column."
                        ],
                    )
                )

        # 3. Plain direct pass-through columns with no mask -- recorded for
        #    a complete, auditable column inventory per view.
        masked_outputs = {m.output_column for m in view.column_masks}
        for lineage in view.column_lineage:
            if lineage.is_derived or lineage.output_column in masked_outputs:
                continue
            entitlements.append(
                ClsEntitlement(
                    view=view.fq_name,
                    table=lineage.source_table or _primary_base_table(view),
                    column=lineage.output_column,
                    ad_group=None,
                    access_effect="DEFAULT_VISIBLE",
                    source_type="DIRECT",
                )
            )

    return entitlements


def _primary_base_table(view: ViewSecurityDefinition) -> str | None:
    return view.base_tables[0] if view.base_tables else None
