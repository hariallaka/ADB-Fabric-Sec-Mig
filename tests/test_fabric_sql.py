"""Tests for the Fabric SQL analytics endpoint path (fabric_sql/)."""

from __future__ import annotations

import csv
import json
import os

import pytest

from dbx_fabric_security.cli import main
from dbx_fabric_security.extractor.view_parser import parse_view
from dbx_fabric_security.fabric_sql import (
    build_admin_views,
    build_fabric_sql_outputs,
    build_role_plan,
    parse_role_mapping_csv,
    translate_views,
)
from dbx_fabric_security.fabric_sql.grants import RoleMapping

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# The two-view case from the design discussion: different columns AND
# different row filters on the same table, granted to different groups.
V1 = "CREATE VIEW cat.s.v1 AS SELECT c1, c2, c3 FROM cat.s.t1 WHERE c1 > 2"
V2 = "CREATE VIEW cat.s.v2 AS SELECT c4, c5, c6 FROM cat.s.t1 WHERE C2 < 4"
T1_COLUMNS = {"cat.s.t1": ["c1", "c2", "c3", "c4", "c5", "c6", "c7"]}


def _views(*sqls_and_grantees, known=None):
    known = known or set()
    return [parse_view(sql, known_view_names=known, grantees=g) for sql, g in sqls_and_grantees]


def _pipeline(views, mappings, table_columns=None, admin_role="super_business_admin"):
    scripts = translate_views(views, table_columns)
    admin_views, exclusions = build_admin_views(views, scripts, "sec_admin", table_columns)
    plan = build_role_plan(scripts, mappings, admin_views, admin_role)
    files, report = build_fabric_sql_outputs(
        views, scripts, admin_views, exclusions, plan, "sec_admin", admin_role
    )
    return scripts, admin_views, exclusions, plan, files, report


# ---------- views ----------

def test_two_views_keep_their_own_columns_and_filters():
    views = _views((V1, ["grp_a"]), (V2, ["grp_b"]))
    scripts = translate_views(views, T1_COLUMNS)
    by = {s.source_view: s for s in scripts}

    assert all(s.deployable for s in scripts)
    v1 = by["cat.s.v1"].ddl
    v2 = by["cat.s.v2"].ddl
    assert v1.startswith("CREATE OR ALTER VIEW [s].[v1] AS")
    assert "FROM [s].[t1]" in v1 and "[c1] > 2" in v1
    assert "[c4]" not in v1
    assert "[c2] < 4" in v2  # C2 normalized to the physical column's casing
    assert "[c1]" not in v2
    assert any("C2->c2" in w for w in by["cat.s.v2"].warnings)


def test_column_casing_unverified_without_table_columns():
    (script,) = translate_views(_views((V2, ["g"])), None)
    assert script.deployable
    assert "[C2] < 4" in script.ddl
    assert any("casing not verified" in w for w in script.warnings)


def test_catalog_is_dropped_and_booleans_become_bit():
    (script,) = translate_views(
        _views(("CREATE VIEW cat.hr.v AS SELECT a FROM cat.hr.emp WHERE active = true", ["g"])), {}
    )
    assert "FROM [hr].[emp]" in script.ddl
    assert "[cat]" not in script.ddl
    assert "[active] = 1" in script.ddl


@pytest.mark.parametrize(
    "where, expected",
    [
        ("owner = current_user()", "Identity-based predicate"),
        ("is_account_group_member('admins')", "Identity-based predicate"),
        ("is_member('admins')", "Identity-based predicate"),
        ("name ILIKE 'a%'", "ILIKE"),
        ("name RLIKE '^a'", "RLIKE"),
        ("some_udf(a) = 1", "some_udf() has no verified T-SQL translation"),
    ],
)
def test_untranslatable_constructs_block_the_view(where, expected):
    (script,) = translate_views(
        _views((f"CREATE VIEW cat.s.v AS SELECT a, name FROM cat.s.t WHERE {where}", ["g"])), {}
    )
    assert not script.deployable
    assert any(expected in i for i in script.blocking_issues), script.blocking_issues


def test_boolean_projection_and_order_by_block():
    (s1,) = translate_views(_views(("CREATE VIEW cat.s.v AS SELECT a > 1 AS big FROM cat.s.t", ["g"])), {})
    (s2,) = translate_views(_views(("CREATE VIEW cat.s.v AS SELECT a FROM cat.s.t ORDER BY a", ["g"])), {})
    assert any("boolean expression" in i for i in s1.blocking_issues)
    assert any("ORDER BY without LIMIT" in i for i in s2.blocking_issues)


def test_cross_catalog_and_unqualified_tables_block():
    (s1,) = translate_views(_views(("CREATE VIEW cat.s.v AS SELECT a FROM other.s.t", ["g"])), {})
    (s2,) = translate_views(_views(("CREATE VIEW cat.s.v AS SELECT a FROM t", ["g"])), {})
    assert any("Cross-catalog" in i for i in s1.blocking_issues)
    assert any("Unqualified table" in i for i in s2.blocking_issues)


def test_cte_reference_is_not_treated_as_unqualified_table():
    (s,) = translate_views(
        _views(("CREATE VIEW cat.s.v AS WITH x AS (SELECT a FROM cat.s.t) SELECT a FROM x", ["g"])), {}
    )
    assert s.deployable, s.blocking_issues


def test_nested_view_ordered_after_base_and_blocked_with_it():
    base_ok = "CREATE VIEW cat.s.base AS SELECT a FROM cat.s.t"
    base_bad = "CREATE VIEW cat.s.base AS SELECT a FROM cat.s.t WHERE a = current_user()"
    child = "CREATE VIEW cat.s.child AS SELECT a FROM cat.s.base"
    known = {"base", "child"}

    ordered = translate_views(_views((child, ["g"]), (base_ok, ["g"]), known=known), {})
    assert [s.source_view for s in ordered] == ["cat.s.base", "cat.s.child"]
    assert ordered[1].depends_on == ["cat.s.base"]

    ordered = translate_views(_views((child, ["g"]), (base_bad, ["g"]), known=known), {})
    child_script = next(s for s in ordered if s.source_view == "cat.s.child")
    assert not child_script.deployable
    assert any("Depends on view 'cat.s.base'" in i for i in child_script.blocking_issues)


# ---------- admin views ----------

def test_admin_view_is_union_of_columns_and_or_of_filters():
    views = _views((V1, ["grp_a"]), (V2, ["grp_b"]))
    scripts = translate_views(views, T1_COLUMNS)
    (admin,), exclusions = build_admin_views(views, scripts, "sec_admin", T1_COLUMNS)

    assert exclusions == []
    assert admin.target_name == "[sec_admin].[s__t1]"
    assert admin.columns == ["c1", "c2", "c3", "c4", "c5", "c6"]  # not c7: no view exposes it
    assert admin.predicates == ["[c1] > 2", "[c2] < 4"]
    assert "WHERE\n  ([c1] > 2)\n  OR ([c2] < 4);" in admin.ddl


def test_admin_view_without_where_gets_all_rows():
    views = _views((V1, ["a"]), ("CREATE VIEW cat.s.v3 AS SELECT c7 FROM cat.s.t1", ["b"]))
    scripts = translate_views(views, T1_COLUMNS)
    (admin,), _ = build_admin_views(views, scripts, "sec_admin", T1_COLUMNS)
    assert admin.predicates == []
    assert "WHERE" not in admin.ddl
    assert admin.warnings


def test_admin_strips_table_alias_from_predicate():
    views = _views(("CREATE VIEW cat.s.v AS SELECT o.c1 FROM cat.s.t1 o WHERE o.c2 = 1", ["g"]))
    scripts = translate_views(views, T1_COLUMNS)
    (admin,), _ = build_admin_views(views, scripts, "sec_admin", T1_COLUMNS)
    assert admin.predicates == ["[c2] = 1"]


def test_admin_excludes_ungranted_joined_and_blocked_views():
    views = _views(
        ("CREATE VIEW cat.s.ungranted AS SELECT c1 FROM cat.s.t1", []),
        ("CREATE VIEW cat.s.joined AS SELECT a.c1 FROM cat.s.t1 a JOIN cat.s.t2 b ON a.c1 = b.c1", ["g"]),
        ("CREATE VIEW cat.s.identity AS SELECT c1 FROM cat.s.t1 WHERE c3 = current_user()", ["g"]),
    )
    scripts = translate_views(views, T1_COLUMNS)
    admin_views, exclusions = build_admin_views(views, scripts, "sec_admin", T1_COLUMNS)
    assert admin_views == []
    reasons = {e.source_view: e.reason for e in exclusions}
    assert "No SELECT grantee" in reasons["cat.s.ungranted"]
    assert "Multi-table" in reasons["cat.s.joined"]
    assert "needs review" in reasons["cat.s.identity"]


def test_admin_star_expands_from_table_columns_or_is_excluded():
    star = "CREATE VIEW cat.s.v AS SELECT * FROM cat.s.t1 WHERE c1 > 0"
    views = _views((star, ["g"]))
    scripts = translate_views(views, T1_COLUMNS)
    (admin,), _ = build_admin_views(views, scripts, "sec_admin", T1_COLUMNS)
    assert admin.columns == T1_COLUMNS["cat.s.t1"]

    scripts = translate_views(views, None)
    admin_views, exclusions = build_admin_views(views, scripts, "sec_admin", None)
    assert admin_views == [] and "SELECT *" in exclusions[0].reason


# ---------- roles and grants ----------

def test_grants_are_per_view_never_on_base_table():
    views = _views((V1, ["grp_a"]), (V2, ["grp_b"]))
    mappings = [
        RoleMapping("grp_a", "role_a", "grp_a"),
        RoleMapping("grp_b", "role_b", "grp_b"),
        RoleMapping("grp_admin", "super_business_admin", "sg-admins"),
    ]
    *_, plan, files, _ = _pipeline(views, mappings, T1_COLUMNS)

    assert plan.role_grants["role_a"] == {"cat": ["[s].[v1]"]}
    assert plan.role_grants["role_b"] == {"cat": ["[s].[v2]"]}
    assert plan.role_grants["super_business_admin"] == {"cat": ["[sec_admin].[s__t1]"]}
    assert plan.role_members["super_business_admin"] == ["sg-admins"]

    script = files["cat__deploy.sql"]
    assert "GRANT SELECT ON [s].[v1] TO [role_a];" in script
    assert "GRANT SELECT ON [s].[v2] TO [role_b];" in script
    assert "ALTER ROLE [super_business_admin] ADD MEMBER [sg-admins];" in script
    assert "ON [s].[t1]" not in script  # base table is never granted
    # sections in executable order
    order = [script.index(m) for m in ("CREATE ROLE", "CREATE OR ALTER VIEW [s].[v1]",
                                         "CREATE OR ALTER VIEW [sec_admin]", "GRANT SELECT")]
    assert order == sorted(order)


def test_unmapped_grantee_gets_nothing():
    views = _views((V1, ["grp_a", "grp_unknown"]))
    *_, plan, files, _ = _pipeline(views, [RoleMapping("grp_a", "role_a", "grp_a")], T1_COLUMNS)
    assert plan.unmapped_grantees == [{"view": "cat.s.v1", "adGroup": "grp_unknown"}]
    assert "grp_unknown" not in files["cat__deploy.sql"]


def test_blocked_view_withholds_grants_and_goes_to_review_file():
    views = _views(("CREATE VIEW cat.s.v AS SELECT c1 FROM cat.s.t1 WHERE c3 = current_user()", ["grp_a"]))
    *_, plan, files, report = _pipeline(views, [RoleMapping("grp_a", "role_a", "grp_a")], T1_COLUMNS)
    assert plan.role_grants == {}
    assert plan.withheld_grants == [{"view": "cat.s.v", "grantees": ["grp_a"]}]
    assert "GRANT" not in files["cat__deploy.sql"].split("===== 5.")[1]
    review = files["cat__needs_review.sql"]
    assert all(line.startswith("--") for line in review.splitlines() if line.strip())
    assert report["summary"]["needsReviewViews"] == 1


def test_role_shared_by_groups_with_different_access_is_flagged():
    views = _views((V1, ["grp_a"]), (V2, ["grp_b"]))
    mappings = [RoleMapping("grp_a", "shared", "grp_a"), RoleMapping("grp_b", "shared", "grp_b")]
    *_, plan, _, _ = _pipeline(views, mappings, T1_COLUMNS)
    (warning,) = plan.overgrant_warnings
    assert warning["fabricRole"] == "shared"
    assert warning["viewsByGroup"] == {"grp_a": ["cat.s.v1"], "grp_b": ["cat.s.v2"]}


def test_admin_role_without_members_warns():
    views = _views((V1, ["grp_a"]))
    *_, plan, _, _ = _pipeline(views, [RoleMapping("grp_a", "role_a", "grp_a")], T1_COLUMNS)
    assert any("has no AD group" in w for w in plan.warnings)


def test_parse_role_mapping_csv(tmp_path):
    p = tmp_path / "m.csv"
    p.write_text("ad_group,fabric_role,fabric_principal\n g1 ,r1,\ng1,r2,Entra G1\n,,\n", encoding="utf-8")
    rows = parse_role_mapping_csv(str(p))
    assert [(r.ad_group, r.fabric_role, r.fabric_principal) for r in rows] == [
        ("g1", "r1", "g1"), ("g1", "r2", "Entra G1"),
    ]
    bad = tmp_path / "bad.csv"
    bad.write_text("group,role\ng,r\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing column"):
        parse_role_mapping_csv(str(bad))


def test_identifier_quoting_escapes_brackets():
    views = _views(("CREATE VIEW cat.s.v AS SELECT c1 FROM cat.s.t1", ["g]x"]))
    *_, files, _ = _pipeline(views, [RoleMapping("g]x", "r]1", "g]x")], T1_COLUMNS)
    assert "ALTER ROLE [r]]1] ADD MEMBER [g]]x];" in files["cat__deploy.sql"]


# ---------- CLI ----------

def test_cli_generate_fabric_sql_on_sample_fixtures(tmp_path, capsys):
    args = [
        "generate-fabric-sql",
        "--views", os.path.join(FIXTURES, "sample_views.sql"),
        "--grants", os.path.join(FIXTURES, "grants_sample.csv"),
        "--table-columns", os.path.join(FIXTURES, "table_columns_sample.json"),
        "--role-mapping", os.path.join(FIXTURES, "role_mapping_sample.csv"),
        "--out-dir", str(tmp_path),
    ]
    assert main(args) == 0
    out = tmp_path / "fabric_sql"
    assert {p.name for p in out.iterdir()} == {
        "sec__deploy.sql", "sec__needs_review.sql", "fabric_sql_report.json", "fabric_view_grants.csv",
    }
    report = json.loads((out / "fabric_sql_report.json").read_text())
    assert report["summary"]["needsReviewViews"] == 1  # v_my_expense_reports (current_user)
    assert report["summary"]["unmappedGrantees"] == 1  # hr_contractor
    with open(out / "fabric_view_grants.csv", newline="") as fh:
        statuses = {r["status"] for r in csv.DictReader(fh)}
    assert statuses == {"granted", "unmapped_grantee", "withheld_view_needs_review"}

    # --strict turns those issues into a failing exit code for a pipeline gate
    assert main(args + ["--strict"]) == 1
    assert "STRICT" in capsys.readouterr().out
