"""Command-line entrypoint for the Databricks -> Fabric security migration
toolkit.

    python -m dbx_fabric_security.cli run-all \\
        --views tests/fixtures/sample_views.sql \\
        --ags-export tests/fixtures/ags_export_sample.csv \\
        --out-dir out/

Subcommands:
    extract             Parse a local view SQL file -> per-view security definition JSON.
    extract-databricks  Pull view DDL live from Unity Catalog, then extract (see
                         README "Running the stages separately" -- this is the
                         Databricks-side step, runnable independently of Fabric).
    translate           Extract + translate -> CLS/RLS entitlement + Fabric role JSON.
    map-roles           Translate + AGS export -> AGS/AD Group/Fabric Role mapping CSV.
    deploy              Translate + a target map -> apply (or dry-run) Fabric roles.
    run-all             Runs extract -> translate -> map-roles -> deploy(dry-run) and
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
from dbx_fabric_security.extractor.view_parser import parse_views_file
from dbx_fabric_security.fabric_api.client import FabricApiClient
from dbx_fabric_security.fabric_api.deploy import deploy_roles
from dbx_fabric_security.mapping.role_mapper import (
    build_role_mapping,
    group_directory,
    load_ags_export,
)
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


def _run_extraction(views_path: str) -> list:
    return parse_views_file(views_path)


def _run_translation(views: list) -> tuple[list, list, list]:
    cls_entitlements = translate_cls(views)
    rls_entitlements = translate_rls(views)
    return cls_entitlements, rls_entitlements, views


def cmd_extract(args: argparse.Namespace) -> None:
    views = _run_extraction(args.views)
    os.makedirs(args.out_dir, exist_ok=True)
    payload = [dataclasses.asdict(v) for v in views]
    _write_json(os.path.join(args.out_dir, "view_security_definitions.json"), payload)
    print(f"Extracted {len(views)} view(s) -> {args.out_dir}/view_security_definitions.json")
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

    os.makedirs(args.out_dir, exist_ok=True)
    sql_path = os.path.join(args.out_dir, "extracted_views.sql")

    if not args.execute:
        print(
            "DRY-RUN: no Databricks call was made (pass --execute with a valid "
            "--token to fetch live view DDL). Nothing written."
        )
        return

    with open(sql_path, "w", encoding="utf-8") as fh:
        for ddl in ddl_by_view.values():
            fh.write(ddl.rstrip().rstrip(";") + ";\n\n")

    print(f"Fetched {len(ddl_by_view)} view definition(s) from {args.catalog} -> {sql_path}")

    # Reuse the exact same parsing path as the file-based `extract` command so
    # downstream translate/map-roles/deploy behave identically regardless of
    # whether extraction ran against a live workspace or a static SQL file.
    views = parse_views_file(sql_path)
    payload = [dataclasses.asdict(v) for v in views]
    _write_json(os.path.join(args.out_dir, "view_security_definitions.json"), payload)
    unsupported = [v.fq_name for v in views if v.unsupported_constructs]
    print(f"Extracted {len(views)} view(s) -> {args.out_dir}/view_security_definitions.json")
    if unsupported:
        print(f"  {len(unsupported)} view(s) flagged for manual review: {unsupported}")


def cmd_translate(args: argparse.Namespace) -> None:
    views = _run_extraction(args.views)
    cls_entitlements, rls_entitlements, _ = _run_translation(views)

    group_dir = {}
    if args.ags_export:
        group_dir = group_directory(load_ags_export(args.ags_export))

    fabric_roles = build_fabric_roles(cls_entitlements, rls_entitlements, group_dir)

    os.makedirs(args.out_dir, exist_ok=True)
    _write_json(os.path.join(args.out_dir, "cls_entitlements.json"), [e.as_dict() for e in cls_entitlements])
    _write_json(os.path.join(args.out_dir, "rls_entitlements.json"), [e.as_dict() for e in rls_entitlements])
    _write_json(os.path.join(args.out_dir, "fabric_data_access_roles.json"), fabric_roles)
    _write_csv(os.path.join(args.out_dir, "cls_entitlements.csv"), [e.as_dict() for e in cls_entitlements])
    _write_csv(os.path.join(args.out_dir, "rls_entitlements.csv"), [e.as_dict() for e in rls_entitlements])

    print(f"CLS entitlements: {len(cls_entitlements)} | RLS entitlements: {len(rls_entitlements)} | "
          f"Fabric roles: {len(fabric_roles)} -> {args.out_dir}/")


def cmd_map_roles(args: argparse.Namespace) -> None:
    views = _run_extraction(args.views)
    cls_entitlements, rls_entitlements, _ = _run_translation(views)
    ags_records = load_ags_export(args.ags_export)
    fabric_roles = build_fabric_roles(cls_entitlements, rls_entitlements, group_directory(ags_records))
    mapping_rows = build_role_mapping(fabric_roles, ags_records)

    os.makedirs(args.out_dir, exist_ok=True)
    _write_json(os.path.join(args.out_dir, "ags_role_mapping.json"), mapping_rows)
    _write_csv(os.path.join(args.out_dir, "ags_role_mapping.csv"), mapping_rows)

    unresolved = [r["adGroupName"] for r in mapping_rows if r["unresolvedAdGroup"]]
    print(f"Role mapping rows: {len(mapping_rows)} -> {args.out_dir}/ags_role_mapping.csv")
    if unresolved:
        print(f"  WARNING: {len(unresolved)} AD group(s) not found in AGS export: {unresolved}")


def cmd_deploy(args: argparse.Namespace) -> None:
    views = _run_extraction(args.views)
    cls_entitlements, rls_entitlements, _ = _run_translation(views)

    group_dir = {}
    if args.ags_export:
        group_dir = group_directory(load_ags_export(args.ags_export))
    fabric_roles = build_fabric_roles(cls_entitlements, rls_entitlements, group_dir)

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
    if args.ags_export:
        print("== Step 3/4: map-roles ==")
        cmd_map_roles(args)
    else:
        print("== Step 3/4: map-roles (skipped, no --ags-export supplied) ==")
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
        p.add_argument("--out-dir", default="out", help="Directory to write output artifacts to")

    p_extract = sub.add_parser("extract", help="Parse a local view SQL file into structured security definitions")
    common(p_extract)
    p_extract.set_defaults(func=cmd_extract)

    p_extract_dbx = sub.add_parser(
        "extract-databricks",
        help="Pull view DDL live from Unity Catalog (Databricks-side step, no Fabric credentials used)",
    )
    p_extract_dbx.add_argument("--workspace-url", required=True, help="e.g. https://adb-1234567890123456.7.azuredatabricks.net")
    p_extract_dbx.add_argument("--warehouse-id", required=True, help="SQL warehouse id used to run the extraction query")
    p_extract_dbx.add_argument("--catalog", required=True, help="Unity Catalog catalog to scan")
    p_extract_dbx.add_argument("--schema", default=None, help="Restrict to one schema (default: whole catalog)")
    p_extract_dbx.add_argument("--token", default=os.environ.get("DATABRICKS_TOKEN"), help="PAT or AAD service-principal token; defaults to $DATABRICKS_TOKEN")
    p_extract_dbx.add_argument("--execute", action="store_true", help="Actually call Databricks (default: dry-run, no network call)")
    p_extract_dbx.add_argument("--out-dir", default="out", help="Directory to write extracted_views.sql and view_security_definitions.json to")
    p_extract_dbx.set_defaults(func=cmd_extract_databricks)

    p_translate = sub.add_parser("translate", help="Extract + translate into CLS/RLS entitlements and Fabric roles")
    common(p_translate)
    p_translate.add_argument("--ags-export", help="AGS export CSV for AD group object-id enrichment")
    p_translate.set_defaults(func=cmd_translate)

    p_map = sub.add_parser("map-roles", help="Build the AGS -> AD Group -> Fabric Role mapping report")
    common(p_map)
    p_map.add_argument("--ags-export", required=True, help="AGS export CSV")
    p_map.set_defaults(func=cmd_map_roles)

    p_deploy = sub.add_parser("deploy", help="Deploy translated roles to Fabric (dry-run by default)")
    common(p_deploy)
    p_deploy.add_argument("--ags-export", help="AGS export CSV for AD group object-id enrichment")
    p_deploy.add_argument("--targets", required=True, help="JSON file mapping table -> {workspaceId, itemId}")
    p_deploy.add_argument("--bearer-token", default=os.environ.get("FABRIC_API_TOKEN"))
    p_deploy.add_argument("--apply", action="store_true", help="Actually call the Fabric API (default: dry-run)")
    p_deploy.set_defaults(func=cmd_deploy)

    p_all = sub.add_parser("run-all", help="Run the full extract -> translate -> map-roles -> deploy pipeline")
    common(p_all)
    p_all.add_argument("--ags-export")
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
