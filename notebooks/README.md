# Interactive extraction (Databricks notebook)

`extract_view_security.py` is a Databricks notebook (import it via
Workspace → Import, or check this repo out as a Databricks Repo and open it
directly) that runs the same extraction the CLI's `extract-databricks`
command does, but **as you, the logged-in user** -- no service principal,
PAT, or `DATABRICKS_TOKEN` needed.

Use this when you want a quick, one-off look at what a catalog would
extract to, or to hand-produce `extracted_views.sql` /
`extracted_grants.csv` for someone to feed into the Fabric-side CLI without
setting up a pipeline identity first.

## Running it

1. Attach the notebook to any SQL-capable cluster/warehouse-backed compute.
2. Set the widgets at the top: `catalog` (required), `schema` (optional,
   blank = whole catalog), `output_path` (a DBFS path, defaults to
   `/dbfs/FileStore/dbx_fabric_security`), and whether to attempt object-id
   resolution.
3. Run all cells.

## What it produces

Same artifacts as `dbx_fabric_security.cli extract-databricks`:

- `extracted_views.sql` -- reconstructed `CREATE VIEW` DDL for every view in
  scope.
- `extracted_grants.csv` -- `view,principal,principal_object_id,privilege`,
  one row per SELECT grant. The last cell in step 4 also prints this CSV's
  contents directly into the notebook output, so you can copy it straight
  into a file without downloading from DBFS if that's easier.
- `extracted_table_columns.json` -- each base table's real column list
  (step 5b), used to correctly attribute an unqualified column in a
  *joined* view to its actual source table instead of guessing. Only
  matters if you have views that join tables and reference a column
  without a table alias (e.g. `SELECT region_name FROM orders o JOIN
  regions r ON ...` where `region_name` actually lives on `regions`) --
  see the main README's "Column-to-table attribution". Requires the
  toolkit import in step 5a.

Steps 5a-5c optionally also produce `view_security_definitions.json` (the
structured extraction result), if this repo's `src/` is importable from the
notebook (e.g. checked out as a Databricks Repo) -- otherwise skip them and
run `dbx_fabric_security.cli translate` on the CSV/SQL/JSON artifacts from
wherever you copy them to.

## The one thing to watch for

This notebook sees exactly what **you** can see in Unity Catalog -- nothing
more. `information_schema.table_privileges` silently omits grants you don't
have visibility into (it never errors); if you're not the catalog owner and
don't hold `MANAGE` or admin, you may see far fewer grantees than actually
exist. The notebook doesn't try to detect this for you — cross-check the
grant counts against what you expect. For a pipeline identity that needs
the *complete* picture reliably, use `grant-catalog-access` (see the main
README's "RBAC / permissions required" → Databricks side) to make that
identity a catalog owner first, rather than relying on interactive access.
