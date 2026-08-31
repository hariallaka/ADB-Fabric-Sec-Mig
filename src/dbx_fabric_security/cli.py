"""Command-line entrypoint for the Databricks -> Fabric security migration
toolkit.

    python -m dbx_fabric_security.cli run-all \\
        --views tests/fixtures/sample_views.sql \\
        --grants tests/fixtures/grants_sample.csv \\
        --out-dir out/

Subcommands:
    extract               Parse a local view SQL file -> per-view security definition JSON.
    extract-databricks    Pull view DDL + SELECT grants + principal object ids live from
                           Unity Catalog, then extract (see README "Running the stages
                           separately" -- this is the Databricks-side step, runnable
                           independently of Fabric).
    grant-catalog-access  One-time bootstrap, run by a catalog owner/admin (not the
                           extraction identity): makes the extraction service principal
                           able to see every view's definition and every grant in a
                           catalog. See README "RBAC / permissions required".
    translate              Extract + translate -> CLS/RLS entitlement + Fabric role JSON.
    map-roles               Extract + translate -> AD Group/Fabric Role mapping report.
    deploy                 Translate + a target map -> apply (or dry-run) Fabric roles.
    run-all                 Runs extract -> translate -> map-roles -> deploy(dry-run) and
                            writes every artifact to --out-dir (local-file source only).
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import sys

from dbx_fabric_security.extractor.databricks_client import DatabricksApiClient
from dbx_fabric_security.extractor.grants import parse_grants_csv
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.fabric_api.client import FabricApiClient
from dbx_fabric_security.fabric_api.deploy import deploy_roles
from dbx_fabric_security.mapping.role_mapper import build_role_mapping
from dbx_fabric_security.translator.cls_translator import translate_cls
from dbx_fabric_security.translator.rls_translator import translate_rls
from dbx_fabric_security.translator.role_builder import build_fabric_roles


def _write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def _write_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("")
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in row.items()}
            )


def _write_grants_csv(path: str, grants_by_view: dict[str, list[str]], principal_directory: dict[str, str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["view", "principal", "principal_object_id", "privilege"])
        for view, principals in grants_by_view.items():
            for principal in principals:
                writer.writerow([view, principal, principal_directory.get(principal, ""), "SELECT"])


def _run_extraction(views_path: str, grants_path: str | None) -> tuple[list, dict[str, str]]:
    grants_by_view, principal_directory = parse_grants_csv(grants_path) if grants_path else ({}, {})
    views = parse_views_file(views_path, grants_by_view=grants_by_view)
    return views, principal_directory


def _run_translation(views: list) -> tuple[list, list]:
    return translate_cls(views), translate_rls(views)


def cmd_extract(args: argparse.Namespace) -> None:
    views, _ = _run_extraction(args.views, args.grants)
    os.makedirs(args.out_dir, exist_ok=True)
    payload = [dataclasses.asdict(v) for v in views]
    _write_json(os.path.join(args.out_dir, "view_security_definitions.json"), payload)
    print(f"Extracted {len(views)} view(s) -> {args.out_dir}/view_security_definitions.json")
    ungranted = [v.fq_name for v in views if not v.grantees]
    if ungranted:
        print(f"  {len(ungranted)} view(s) have no recorded SELECT grantees (no --grants supplied, "
              f"or none found): {ungranted}")
    unsupported = [v.fq_name for v in views if v.unsupported_constructs]
    if unsupported:
        print(f"  {len(unsupported)} view(s) flagged for manual review: {unsupported}")


def cmd_extract_databricks(args: argparse.Namespace) -> None:
    """Databricks-side extraction step. Requires only Databricks connectivity
    (workspace URL, SQL warehouse, and a token scoped per README's
    "Databricks RBAC" section) -- no Fabric credentials are used here, so
    this can run as its own Azure DevOps stage, its own pipeline, or even a
    Databricks Job task, independently of the Fabric-side steps.
    """
    client = DatabricksApiClient(
        workspace_url=args.workspace_url,
        bearer_token=args.token,
        dry_run=not args.execute,
    )
    ddl_by_view = client.fetch_view_ddl(args.warehouse_id, args.catalog, args.schema)
    grants_by_view = client.fetch_view_grants(args.warehouse_id, args.catalog, args.schema)

    os.makedirs(args.out_dir, exist_ok=True)
    sql_path = os.path.join(args.out_dir, "extracted_views.sql")
    grants_path = os.path.join(args.out_dir, "extracted_grants.csv")

    if not args.execute:
        print(
            "DRY-RUN: no Databricks call was made (pass --execute with a valid "
            "--token to fetch live view DDL + grants + principal object ids). Nothing written."
        )
        return

    all_principals = sorted({p for principals in grants_by_view.values() for p in principals})
    principal_directory = client.fetch_principal_directory(all_principals)
    unresolved = [p for p in all_principals if p not in principal_directory]

    with open(sql_path, "w", encoding="utf-8") as fh:
        for ddl in ddl_by_view.values():
            fh.write(ddl.rstrip().rstrip(";") + ";\n\n")
    _write_grants_csv(grants_path, grants_by_view, principal_directory)

    print(f"Fetched {len(ddl_by_view)} view definition(s), grants for {len(grants_by_view)} view(s), "
          f"and object ids for {len(principal_directory)}/{len(all_principals)} principal(s) "
          f"from {args.catalog} -> {sql_path}, {grants_path}")
    if unresolved:
        print(f"  {len(unresolved)} principal(s) could not be resolved to an Azure AD object id "
              f"via SCIM (not found as a Databricks group or user): {unresolved}")

    # Reuse the exact same parsing path as the file-based `extract` command so
    # downstream translate/map-roles/deploy behave identically regardless of
    # whether extraction ran against a live workspace or a static SQL file.
    views = parse_views_file(sql_path, grants_by_view=grants_by_view)
    payload = [dataclasses.asdict(v) for v in views]
    _write_json(os.path.join(args.out_dir, "view_security_definitions.json"), payload)
    ungranted = [v.fq_name for v in views if not v.grantees]
    unsupported = [v.fq_name for v in views if v.unsupported_constructs]
    print(f"Extracted {len(views)} view(s) -> {args.out_dir}/view_security_definitions.json")
    if ungranted:
        print(f"  {len(ungranted)} view(s) have no SELECT grantees in Unity Catalog: {ungranted}")
    if unsupported:
        print(f"  {len(unsupported)} view(s) flagged for manual review: {unsupported}")


def cmd_grant_catalog_access(args: argparse.Namespace) -> None:
    """One-time bootstrap step. Must be run with a catalog owner's or
    metastore admin's own token -- never with the extraction service
    principal's token, since it doesn't have this privilege yet (that's the
    whole point of this command).
    """
    client = DatabricksApiClient(
        workspace_url=args.workspace_url,
        bearer_token=args.token,
        dry_run=not args.execute,
    )
    result = client.grant_catalog_access(args.warehouse_id, args.catalog, args.principal, args.mode)

    if not args.execute:
        print(f"DRY-RUN: would run on {args.catalog}: {result.payload['statement']}")
        return

    print(f"Applied to {args.catalog}: {result.payload['statement']}")


def cmd_translate(args: argparse.Namespace) -> None:
    views, principal_dir = _run_extraction(args.views, args.grants)
    cls_entitlements, rls_entitlements = _run_translation(views)

    fabric_roles = build_fabric_roles(cls_entitlements, rls_entitlements, principal_dir)

    os.makedirs(args.out_dir, exist_ok=True)
    _write_json(os.path.join(args.out_dir, "cls_entitlements.json"), [e.as_dict() for e in cls_entitlements])
    _write_json(os.path.join(args.out_dir, "rls_entitlements.json"), [e.as_dict() for e in rls_entitlements])
    _write_json(os.path.join(args.out_dir, "fabric_data_access_roles.json"), fabric_roles)
    _write_csv(os.path.join(args.out_dir, "cls_entitlements.csv"), [e.as_dict() for e in cls_entitlements])
    _write_csv(os.path.join(args.out_dir, "rls_entitlements.csv"), [e.as_dict() for e in rls_entitlements])

    print(f"CLS entitlements: {len(cls_entitlements)} | RLS entitlements: {len(rls_entitlements)} | "
          f"Fabric roles: {len(fabric_roles)} -> {args.out_dir}/")


def cmd_map_roles(args: argparse.Namespace) -> None:
    views, principal_dir = _run_extraction(args.views, args.grants)
    cls_entitlements, rls_entitlements = _run_translation(views)
    fabric_roles = build_fabric_roles(cls_entitlements, rls_entitlements, principal_dir)
    mapping_rows = build_role_mapping(fabric_roles)

    os.makedirs(args.out_dir, exist_ok=True)
    _write_json(os.path.join(args.out_dir, "role_mapping.json"), mapping_rows)
    _write_csv(os.path.join(args.out_dir, "role_mapping.csv"), mapping_rows)

    unresolved = [r["principalName"] for r in mapping_rows if r["unresolvedPrincipalObjectId"]]
    print(f"Role mapping rows: {len(mapping_rows)} -> {args.out_dir}/role_mapping.csv")
    if unresolved:
        print(f"  WARNING: {len(unresolved)} principal(s) have no known object id "
              f"(not in --grants' principal_object_id column): {unresolved}")


def cmd_deploy(args: argparse.Namespace) -> None:
    views, principal_dir = _run_extraction(args.views, args.grants)
    cls_entitlements, rls_entitlements = _run_translation(views)
    fabric_roles = build_fabric_roles(cls_entitlements, rls_entitlements, principal_dir)

    with open(args.targets, encoding="utf-8") as fh:
        raw_targets = json.load(fh)
    table_targets = {t: (v["workspaceId"], v["itemId"]) for t, v in raw_targets.items()}

    client = FabricApiClient(bearer_token=args.bearer_token, dry_run=not args.apply)
    results = deploy_roles(client, fabric_roles, table_targets)

    os.makedirs(args.out_dir, exist_ok=True)
    report = [
        {
            "table": plan.table,
            "workspaceId": plan.workspace_id,
            "itemId": plan.item_id,
            "rolesApplied": [r["name"] for r in plan.roles_to_apply],
            "rolesRemoved": plan.roles_removed,
            "dryRun": result.dry_run,
            "statusCode": result.status_code,
        }
        for plan, result in results
    ]
    _write_json(os.path.join(args.out_dir, "deployment_report.json"), report)

    skipped = sorted(set(r["table"] for r in fabric_roles) - set(table_targets.keys()))
    mode = "APPLIED" if args.apply else "DRY-RUN"
    print(f"Deployment ({mode}): {len(results)} item(s) targeted -> {args.out_dir}/deployment_report.json")
    if skipped:
        print(f"  Skipped (no target mapping configured): {skipped}")


def cmd_run_all(args: argparse.Namespace) -> None:
    print("== Step 1/4: extract ==")
    cmd_extract(args)
    print("== Step 2/4: translate ==")
    cmd_translate(args)
    print("== Step 3/4: map-roles ==")
    cmd_map_roles(args)
    if args.targets:
        print("== Step 4/4: deploy (dry-run unless --apply) ==")
        cmd_deploy(args)
    else:
        print("== Step 4/4: deploy (skipped, no --targets supplied) ==")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dbx-fabric-security")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--views", required=True, help="Path to a .sql file containing CREATE VIEW statements")
        p.add_argument("--grants", help="Path to a grants CSV (view,principal,principal_object_id,privilege) -- who holds SELECT on each view")
        p.add_argument("--out-dir", default="out", help="Directory to write output artifacts to")

    p_extract = sub.add_parser("extract", help="Parse a local view SQL file into structured security definitions")
    common(p_extract)
    p_extract.set_defaults(func=cmd_extract)

    def common_databricks_connection(p: argparse.ArgumentParser) -> None:
        p.add_argument("--workspace-url", required=True, help="e.g. https://adb-1234567890123456.7.azuredatabricks.net")
        p.add_argument("--warehouse-id", required=True, help="SQL warehouse id used to run the query")
        p.add_argument("--token", default=os.environ.get("DATABRICKS_TOKEN"), help="PAT or AAD token; defaults to $DATABRICKS_TOKEN")
        p.add_argument("--execute", action="store_true", help="Actually call Databricks (default: dry-run, no network call)")

    p_extract_dbx = sub.add_parser(
        "extract-databricks",
        help="Pull view DDL + SELECT grants + principal object ids live from Unity Catalog (no Fabric credentials used)",
    )
    common_databricks_connection(p_extract_dbx)
    p_extract_dbx.add_argument("--catalog", required=True, help="Unity Catalog catalog to scan")
    p_extract_dbx.add_argument("--schema", default=None, help="Restrict to one schema (default: whole catalog)")
    p_extract_dbx.add_argument("--out-dir", default="out", help="Directory to write extracted_views.sql / extracted_grants.csv / view_security_definitions.json to")
    p_extract_dbx.set_defaults(func=cmd_extract_databricks)

    p_grant = sub.add_parser(
        "grant-catalog-access",
        help="One-time bootstrap (run as a catalog owner/admin): let the extraction identity see every view + grant in a catalog",
    )
    common_databricks_connection(p_grant)
    p_grant.add_argument("--catalog", required=True, help="Catalog to grant access on")
    p_grant.add_argument("--principal", required=True, help="The extraction service principal's name or application id")
    p_grant.add_argument("--mode", choices=["owner", "all_privileges"], default="owner", help="Transfer catalog ownership, or grant ALL PRIVILEGES without changing the owner (default: owner)")
    p_grant.set_defaults(func=cmd_grant_catalog_access)

    p_translate = sub.add_parser("translate", help="Extract + translate into CLS/RLS entitlements and Fabric roles")
    common(p_translate)
    p_translate.set_defaults(func=cmd_translate)

    p_map = sub.add_parser("map-roles", help="Build the AD Group/principal -> Fabric Role -> OneLake object mapping report")
    common(p_map)
    p_map.set_defaults(func=cmd_map_roles)

    p_deploy = sub.add_parser("deploy", help="Deploy translated roles to Fabric (dry-run by default)")
    common(p_deploy)
    p_deploy.add_argument("--targets", required=True, help="JSON file mapping table -> {workspaceId, itemId}")
    p_deploy.add_argument("--bearer-token", default=os.environ.get("FABRIC_API_TOKEN"))
    p_deploy.add_argument("--apply", action="store_true", help="Actually call the Fabric API (default: dry-run)")
    p_deploy.set_defaults(func=cmd_deploy)

    p_all = sub.add_parser("run-all", help="Run the full extract -> translate -> map-roles -> deploy pipeline")
    common(p_all)
    p_all.add_argument("--targets")
    p_all.add_argument("--bearer-token", default=os.environ.get("FABRIC_API_TOKEN"))
    p_all.add_argument("--apply", action="store_true")
    p_all.set_defaults(func=cmd_run_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
