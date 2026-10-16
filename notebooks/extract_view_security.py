# Databricks notebook source
# MAGIC %md
# MAGIC # Extract view security (interactive, logged-in-user identity)
# MAGIC
# MAGIC Runs entirely as **you**, the notebook's logged-in user -- no service
# MAGIC principal, PAT, or `extract-databricks` CLI call needed. Useful for a
# MAGIC one-off pull, a quick look at what a catalog would extract to, or for
# MAGIC anyone who can query Unity Catalog interactively but doesn't want to set
# MAGIC up a pipeline identity yet.
# MAGIC
# MAGIC It produces the same artifacts as
# MAGIC `dbx_fabric_security.cli extract-databricks`:
# MAGIC - `extracted_views.sql` -- reconstructed `CREATE VIEW` DDL
# MAGIC - `extracted_grants.csv` -- `view,principal,principal_object_id,privilege`
# MAGIC - `extracted_table_columns.json` -- each base table's real column list,
# MAGIC   used to correctly attribute an unqualified column in a joined view to
# MAGIC   its actual source table (step 5b; requires the repo import in step 5a)
# MAGIC
# MAGIC so you can copy/paste them, download them from DBFS, or feed them
# MAGIC straight into `dbx_fabric_security.cli translate` on the Fabric side.
# MAGIC
# MAGIC **What you'll see if you don't have full access:** this notebook uses
# MAGIC your own Unity Catalog privileges. If you can't see another team's
# MAGIC grants on a view, `information_schema.table_privileges` simply won't
# MAGIC return them -- it never errors, it just quietly omits what you can't
# MAGIC see (Unity Catalog only shows you privileges you hold, granted, or
# MAGIC have owner/MANAGE/admin visibility into). Cross-check the row counts in
# MAGIC the summary cell against what you expect; a low grant count for a
# MAGIC catalog you don't own is a sign you're missing ownership/MANAGE, not
# MAGIC that the views genuinely have few grantees. See the main README's RBAC
# MAGIC section and `grant-catalog-access` for the non-interactive fix.

# COMMAND ----------

dbutils.widgets.text("catalog", "", "Catalog to extract")
dbutils.widgets.text("schema", "", "Schema (blank = whole catalog)")
dbutils.widgets.text("output_path", "/dbfs/FileStore/dbx_fabric_security", "Output directory (DBFS)")
dbutils.widgets.dropdown("resolve_object_ids", "true", ["true", "false"], "Resolve principal object ids (SCIM)")

catalog = dbutils.widgets.get("catalog").strip()
schema = dbutils.widgets.get("schema").strip() or None
output_path = dbutils.widgets.get("output_path").strip()
resolve_object_ids = dbutils.widgets.get("resolve_object_ids") == "true"

assert catalog, "Set the 'catalog' widget before running."

# COMMAND ----------

# MAGIC %md ## 1. Pull view DDL -- via `spark.sql`, using your own identity

# COMMAND ----------

schema_filter = f"table_schema = '{schema}'" if schema else "1=1"

views_df = spark.sql(f"""
    SELECT table_catalog, table_schema, table_name, view_definition
    FROM {catalog}.information_schema.views
    WHERE {schema_filter}
""")

view_rows = views_df.collect()
ddl_by_view = {}
for row in view_rows:
    fq_name = f"{row.table_catalog}.{row.table_schema}.{row.table_name}"
    ddl_by_view[fq_name] = f"CREATE OR REPLACE VIEW {fq_name} AS\n{row.view_definition}"

print(f"Found {len(ddl_by_view)} view(s) in {catalog}" + (f".{schema}" if schema else ""))
display(views_df.select("table_catalog", "table_schema", "table_name"))

# COMMAND ----------

# MAGIC %md ## 2. Pull SELECT grants on those views -- same identity, same caveat as above

# COMMAND ----------

grants_schema_filter = f"v.table_schema = '{schema}'" if schema else "1=1"

grants_df = spark.sql(f"""
    SELECT v.table_catalog, v.table_schema, v.table_name, p.grantee
    FROM {catalog}.information_schema.table_privileges p
    JOIN {catalog}.information_schema.views v
      ON p.table_catalog = v.table_catalog
     AND p.table_schema = v.table_schema
     AND p.table_name = v.table_name
    WHERE p.privilege_type = 'SELECT' AND {grants_schema_filter}
""")

grants_by_view = {}
for row in grants_df.collect():
    fq_name = f"{row.table_catalog}.{row.table_schema}.{row.table_name}"
    grants_by_view.setdefault(fq_name, [])
    if row.grantee not in grants_by_view[fq_name]:
        grants_by_view[fq_name].append(row.grantee)

all_principals = sorted({p for principals in grants_by_view.values() for p in principals})
print(f"Found {len(all_principals)} distinct principal(s) with SELECT across {len(grants_by_view)} view(s)")
display(grants_df)

# COMMAND ----------

# MAGIC %md ## 3. Resolve principal object ids (optional, via SCIM)
# MAGIC
# MAGIC Uses the notebook's own short-lived API token
# MAGIC (`dbutils.notebook.getContext()`) to call the workspace SCIM API --
# MAGIC still your identity, no separate credential. Requires your account to
# MAGIC have SCIM read access (typically workspace admin); if it doesn't, this
# MAGIC cell will simply resolve nothing and every principal comes back
# MAGIC unresolved -- that's expected, not an error, and everything downstream
# MAGIC still works with the object id column left blank for you to fill in
# MAGIC by hand later.

# COMMAND ----------

import requests

principal_directory = {}

if resolve_object_ids and all_principals:
    ctx = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
    notebook_token = ctx.apiToken().getOrElse(None)
    workspace_url = ctx.apiUrl().getOrElse(None)

    def scim_lookup(resource, filter_field, value):
        url = f"{workspace_url}/api/2.0/preview/scim/v2/{resource}"
        headers = {"Authorization": f"Bearer {notebook_token}"}
        escaped = value.replace('"', '\\"')
        resp = requests.get(url, headers=headers, params={"filter": f'{filter_field} eq "{escaped}"'}, timeout=30)
        resp.raise_for_status()
        resources = resp.json().get("Resources", [])
        return resources[0] if resources else None

    for name in all_principals:
        group = scim_lookup("Groups", "displayName", name)
        if group:
            principal_directory[name] = group.get("externalId")
            continue
        user = scim_lookup("Users", "userName", name)
        if user:
            principal_directory[name] = user.get("externalId")

    unresolved = [p for p in all_principals if p not in principal_directory]
    print(f"Resolved {len(principal_directory)}/{len(all_principals)} principal(s) to an Azure AD object id")
    if unresolved:
        print(f"  Unresolved (no SCIM match, or no SCIM read access): {unresolved}")
else:
    print("Skipped object id resolution (resolve_object_ids=false or no grantees found)")

# COMMAND ----------

# MAGIC %md ## 4. Write output -- copy/paste-ready, plus files under DBFS

# COMMAND ----------

import csv
import io
import os

os.makedirs(output_path, exist_ok=True)
sql_path = os.path.join(output_path, "extracted_views.sql")
grants_path = os.path.join(output_path, "extracted_grants.csv")

with open(sql_path, "w", encoding="utf-8") as fh:
    for ddl in ddl_by_view.values():
        fh.write(ddl.rstrip().rstrip(";") + ";\n\n")

grants_buffer = io.StringIO()
writer = csv.writer(grants_buffer)
writer.writerow(["view", "principal", "principal_object_id", "privilege"])
for view, principals in grants_by_view.items():
    for principal in principals:
        writer.writerow([view, principal, principal_directory.get(principal, ""), "SELECT"])

with open(grants_path, "w", encoding="utf-8") as fh:
    fh.write(grants_buffer.getvalue())

print(f"Wrote {sql_path}")
print(f"Wrote {grants_path}")
print()
print("=" * 80)
print("extracted_grants.csv (copy from here if you'd rather paste than download):")
print("=" * 80)
print(grants_buffer.getvalue())

# COMMAND ----------

# MAGIC %md ## 5a. Optional: import the toolkit for the remaining steps
# MAGIC
# MAGIC Only works if this repo is checked out as a Databricks Repo (or the
# MAGIC `dbx_fabric_security` package is otherwise installed on this cluster).
# MAGIC If you'd rather do the rest on the Fabric side instead, skip both 5a and
# MAGIC 5b and take `extracted_views.sql` + `extracted_grants.csv` from step 4
# MAGIC there -- that's the normal, decoupled path (see the main README).
# MAGIC `region_name`-style unqualified-column-in-a-join attribution still works
# MAGIC fine without this; it just falls back to the first base table with an
# MAGIC explicit flag instead of resolving exactly (see the main README).

# COMMAND ----------

import json
import sys

toolkit_available = False
try:
    # Adjust if your Repo is checked out somewhere else.
    repo_src_path = "/Workspace/Repos/<your-checkout>/ADB-Fabric-Sec-Mig/src"
    if repo_src_path not in sys.path:
        sys.path.insert(0, repo_src_path)

    from dbx_fabric_security.extractor.grants import parse_grants_csv
    from dbx_fabric_security.extractor.view_parser import distinct_base_tables, parse_views_file

    toolkit_available = True
    print("dbx_fabric_security imported -- steps 5b/5c will run.")
except ImportError as exc:
    print(f"Skipped -- dbx_fabric_security package not importable here ({exc}). "
          f"That's fine: use extracted_views.sql + extracted_grants.csv from step 4 instead.")

# COMMAND ----------

# MAGIC %md ## 5b. Optional: resolve base table columns, for correct join attribution
# MAGIC
# MAGIC Same purpose as `DatabricksApiClient.fetch_table_columns`, just run
# MAGIC directly via `spark.sql` instead of a REST call, since we're already
# MAGIC running inside Databricks. Only matters for a *joined* view with an
# MAGIC *unqualified* column -- see the main README's "Column-to-table
# MAGIC attribution".

# COMMAND ----------

table_columns = {}

if toolkit_available:
    provisional_grants, _ = parse_grants_csv(grants_path)
    provisional_views = parse_views_file(sql_path, grants_by_view=provisional_grants)
    all_base_tables = distinct_base_tables(provisional_views)

    by_catalog = {}
    for fqn in all_base_tables:
        parts = fqn.split(".")
        if len(parts) == 3:
            by_catalog.setdefault(parts[0], []).append(f"{parts[1]}.{parts[2]}")

    for cat, schema_tables in by_catalog.items():
        quoted = ", ".join("'" + st.replace("'", "''") + "'" for st in schema_tables)
        cols_df = spark.sql(f"""
            SELECT table_catalog, table_schema, table_name, column_name
            FROM {cat}.information_schema.columns
            WHERE CONCAT(table_schema, '.', table_name) IN ({quoted})
            ORDER BY ordinal_position
        """)
        for row in cols_df.collect():
            fq = f"{row.table_catalog}.{row.table_schema}.{row.table_name}"
            table_columns.setdefault(fq, []).append(row.column_name)

    table_columns_path = os.path.join(output_path, "extracted_table_columns.json")
    with open(table_columns_path, "w", encoding="utf-8") as fh:
        json.dump(table_columns, fh, indent=2)
    print(f"Wrote {table_columns_path} ({len(table_columns)}/{len(all_base_tables)} base table(s) resolved)")
else:
    print("Skipped (needs the toolkit import from 5a).")

# COMMAND ----------

# MAGIC %md ## 5c. Optional: produce `view_security_definitions.json` right here

# COMMAND ----------

if toolkit_available:
    import dataclasses

    grants_for_parse, _ = parse_grants_csv(grants_path)
    views = parse_views_file(sql_path, grants_by_view=grants_for_parse, table_columns=table_columns)

    json_path = os.path.join(output_path, "view_security_definitions.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump([dataclasses.asdict(v) for v in views], fh, indent=2, default=str)

    print(f"Wrote {json_path} ({len(views)} view(s))")
else:
    print("Skipped (needs the toolkit import from 5a).")
