"""Translates extracted Databricks row filters into Fabric-ready row-level
security predicates.

Key translation insight: in a Databricks dynamic view, group membership is
usually checked *inline* in the predicate (``is_account_group_member(...)``).
In Fabric, an AD group is instead bound to a role via role *membership*, and
the role carries its own row-filter predicate. So translation strips the
membership check out of the predicate and instead produces one
(``ad_group`` -> ``predicate``) pair per group -- the membership check
becomes implicit in "this predicate only applies to this role".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dbx_fabric_security.extractor.models import ViewSecurityDefinition


@dataclass
class RlsEntitlement:
    view: str
    table: str | None
    ad_group: str | None
    row_filter_predicate: str
    filter_type: str
    requires_validation: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "view": self.view,
            "table": self.table,
            "adGroup": self.ad_group,
            "rowFilterPredicate": self.row_filter_predicate,
            "filterType": self.filter_type,
            "requiresValidation": self.requires_validation,
            "notes": self.notes,
        }


def _normalize_predicate(predicate: str) -> str:
    """Collapses self-referential tautologies (e.g. ``region = region``,
    produced by CASE branches like ``THEN region`` meaning "no restriction")
    down to an explicit ``TRUE``.
    """
    sides = [s.strip() for s in predicate.split("=", 1)]
    if len(sides) == 2 and sides[0] == sides[1]:
        return "TRUE"
    return predicate


def translate_rls(views: list[ViewSecurityDefinition]) -> list[RlsEntitlement]:
    entitlements: list[RlsEntitlement] = []

    for view in views:
        table = view.base_tables[0] if view.base_tables else None

        for rf in view.row_filters:
            if rf.filter_type in ("GROUP_GATE", "GROUP_ATTRIBUTE"):
                for group, predicate in rf.group_predicates.items():
                    entitlements.append(
                        RlsEntitlement(
                            view=view.fq_name,
                            table=table,
                            ad_group=group,
                            row_filter_predicate=_normalize_predicate(predicate),
                            filter_type=rf.filter_type,
                        )
                    )
            elif rf.filter_type == "USER_MATCH":
                entitlements.append(
                    RlsEntitlement(
                        view=view.fq_name,
                        table=table,
                        ad_group=None,
                        row_filter_predicate=_rewrite_user_predicate(rf.predicate_sql),
                        filter_type="USER_MATCH",
                        requires_validation=True,
                        notes=[
                            "Predicate compares a column against the calling "
                            "user's identity rather than group membership. "
                            "Fabric translation assumes a per-user dynamic "
                            "predicate function (e.g. USERPRINCIPALNAME()) is "
                            "available on the target surface; confirm against "
                            "the current Fabric RLS/OneLake API before relying "
                            "on this in production."
                        ],
                    )
                )
            elif rf.filter_type == "ATTRIBUTE_MATCH":
                entitlements.append(
                    RlsEntitlement(
                        view=view.fq_name,
                        table=table,
                        ad_group=None,
                        row_filter_predicate=rf.predicate_sql,
                        filter_type="ATTRIBUTE_MATCH",
                        requires_validation=True,
                        notes=[
                            "Predicate has no identity function tying it to an "
                            "AD group or user; it is a plain data filter. "
                            "Manual mapping to a target Fabric role is required "
                            "before deployment."
                        ],
                    )
                )
            else:  # UNSUPPORTED
                entitlements.append(
                    RlsEntitlement(
                        view=view.fq_name,
                        table=table,
                        ad_group=None,
                        row_filter_predicate=rf.predicate_sql,
                        filter_type="UNSUPPORTED",
                        requires_validation=True,
                        notes=["Predicate could not be classified; manual translation required."],
                    )
                )

    return entitlements


def _rewrite_user_predicate(predicate_sql: str) -> str:
    return (
        predicate_sql.replace("current_user()", "USERPRINCIPALNAME()")
        .replace("CURRENT_USER()", "USERPRINCIPALNAME()")
        .replace("session_user()", "USERPRINCIPALNAME()")
        .replace("SESSION_USER()", "USERPRINCIPALNAME()")
    )
