# Fabric SQL analytics endpoint path: views + roles over the UC mirror

`generate-fabric-sql` is an alternative to the OneLake data-access-role path
(`translate` / `deploy`). The Databricks extraction is unchanged; only the
Fabric side differs.

## Why this path exists

The OneLake role path merges every view on a table, for the same principal,
into one table-level role (see
[security-role-mapping.md](./security-role-mapping.md#role-creation-strategy)).
That loses information when views on the same table have **different column
lists and different row filters**:

```sql
CREATE VIEW cat.s.v1 AS SELECT c1, c2, c3 FROM cat.s.t1 WHERE c1 > 2;
CREATE VIEW cat.s.v2 AS SELECT c4, c5, c6 FROM cat.s.t1 WHERE c2 < 4;
```

A principal granted both views can see `c1..c3` on rows where `c1 > 2` and
`c4..c6` on rows where `c2 < 4`. Table-level RLS + CLS can only express
"these rows × these columns", so the merged role exposes `c4..c6` on rows
where only `c1 > 2` holds. No combination of one RLS filter and one CLS
column list on `t1` reproduces the two views.

This path keeps each view as a **view** in Fabric and grants access per view,
so the Databricks semantics carry over exactly.

## What it generates

Everything is written to `<out-dir>/fabric_sql/`. There is one deploy script
per Unity Catalog catalog, because each catalog is mirrored as its own Fabric
item with its own SQL analytics endpoint.

| File | Contents |
|---|---|
| `<catalog>__deploy.sql` | Run against that catalog's mirrored item SQL analytics endpoint. Sections: 1. schemas, 2. roles and membership, 3. views (dependency order), 4. super-admin views, 5. `GRANT SELECT` on views to roles. Idempotent (`IF NOT EXISTS`, `CREATE OR ALTER`), batches separated by `GO`. |
| `<catalog>__needs_review.sql` | Views that were **not** translated with confidence. Fully commented out: reasons, Databricks grantees whose access is withheld, original SQL, best-effort T-SQL. Only written when there is something to review. |
| `fabric_sql_report.json` | Per-view status and warnings, admin view definitions, admin exclusions, role plan, unmapped grantees, over-grant warnings. |
| `fabric_view_grants.csv` | Audit trail: one row per `(view, AD group, Fabric role)` with status `granted`, `unmapped_grantee` or `withheld_view_needs_review`. |
| `deployed_state.json` | What the deploy scripts create: views (in creation order), roles, members and grants, per catalog. Keep it after a successful deploy; the next run diffs against it. |
| `<catalog>__revoke.sql` | Only with `--previous-state`. Removes what the previous deployment granted that is no longer wanted. Run it **before** `<catalog>__deploy.sql`. |

### 1. Views, translated to T-SQL

* Name mapping: `catalog.schema.object` becomes `[schema].[object]` in that
  catalog's endpoint. The view keeps its Databricks schema and name.
* Translation uses sqlglot (`databricks` → `tsql`): e.g. `true` → `1`,
  `LIMIT n` → `TOP n`, integer `/` → float division, Spark date functions →
  `DATEADD`/`GETDATE`.
* Column casing is normalized to the physical table's casing when
  `--table-columns` is supplied (`C2` → `c2`). Databricks resolves identifiers
  case-insensitively, but the Fabric endpoint's default collation is
  case-sensitive. Without `--table-columns`, every view carries a warning.
* View-on-view references are created in dependency order. If a base view is
  blocked, its dependents are blocked too.

A view goes to the **needs-review** file, and nobody is granted on it, when
it contains any of these:

| Construct | Reason |
|---|---|
| `current_user()`, `session_user()`, `is_member()`, `is_account_group_member()`, `current_groups()` | Identity resolves differently in Fabric: Entra UPN (`SUSER_SNAME()`) and database roles (`IS_ROLEMEMBER()`). The row filter must be rewritten and tested by hand. |
| Any function sqlglot does not recognise (UDFs, Databricks-only functions) | sqlglot passes these through unchanged, producing T-SQL that fails or behaves differently. |
| `ILIKE`, `RLIKE`/`REGEXP`, `EXPLODE`, `LATERAL VIEW`, `QUALIFY`, `col:path` JSON, `PIVOT`, `TABLESAMPLE`, array/map/struct access or construction, lambdas | No direct T-SQL equivalent. |
| A boolean expression in the SELECT list (`a > 1 AS flag`) | T-SQL cannot project booleans. Use `CASE WHEN`. |
| Top-level `ORDER BY` without `LIMIT` | Invalid in a T-SQL view. |
| A table in another catalog | Needs that catalog's mirrored item name and cross-item permissions. |
| An unqualified table name (not a CTE) | Would resolve against `dbo` in Fabric. |

Joins, aggregates, window functions, subqueries, CTEs and `UNION` are **not**
blocked: the whole view body is carried over, so they translate like any
other SQL.

### 2. Super business admin views

For each base table there is one view `[<admin-schema>].[<schema>__<table>]`,
granted to `--admin-role`:

* **Columns**: the union of every physical column any granted view exposes
  from that table. Derived expressions contribute their source columns, as
  in the CLS rule.
* **Rows**: the `OR` of every such view's `WHERE` clause. If any view has no
  `WHERE`, the result is all rows.

For the `v1`/`v2` example:

```sql
CREATE OR ALTER VIEW [sec_admin].[s__t1] AS
SELECT [c1], [c2], [c3], [c4], [c5], [c6]
FROM [s].[t1]
WHERE ([c1] > 2) OR ([c2] < 4);
```

This is a deliberate over-grant for the admin role: the admin sees `c4..c6`
on `c1 > 2` rows. The admin gets a view, not the base table, so columns no
view exposes (`c7` above) stay hidden.

Views that cannot be folded safely into a single-table predicate are
**excluded** and listed in the report's `adminExclusions`, so the admin gets
less, never more:

* views with no grantee
* views that need review
* views on other views
* multi-table, aggregate, window, subquery or UNION views
* `SELECT *` views when `--table-columns` lacks the base table

### 3. Roles, membership and grants

`--role-mapping` CSV:

```csv
ad_group,fabric_role,fabric_principal
finance_readers,fabric_finance_reader,
sales_region_us,fabric_sales_regional,
sales_region_eu,fabric_sales_regional,
business_admins,super_business_admin,sg-business-admins
```

* `ad_group` must match the Databricks grants output's `principal` exactly.
  There is no case-folding or fuzzy matching, so a typo leaves the group
  unmapped rather than mapped to the wrong role.
* `fabric_principal` (optional) is the name to use in
  `ALTER ROLE ... ADD MEMBER` if the Entra name Fabric sees differs from the
  Databricks group name.
* Members of `--admin-role` come from the rows whose `fabric_role` is the
  admin role. The admin group does not need to appear in the Databricks
  grants.
* A role gets `SELECT` on a view when any group mapped to it holds `SELECT`
  on that view in Unity Catalog. **Nothing is ever granted on a mirrored base
  table.**

Fail-closed rules:

* A grantee with no mapping row gets nothing and is listed as unmapped.
* A view in needs-review gets no grants. Its grantees are listed as withheld.
* A role that holds several groups with **different** Databricks view access
  is flagged (`overgrantWarnings`). Every member of that role gets the union
  of those groups' views. That may be intended, but it is no longer the
  Databricks access model.

### 4. Revoking access that is no longer wanted

`CREATE OR ALTER` and `GRANT` only add, so on their own a group removed in
Databricks would keep its Fabric access. Pass the previous run's
`deployed_state.json` as `--previous-state` and the run diffs the previous
intended state against the new one. For each catalog where anything was
removed it writes `<catalog>__revoke.sql`:

| Removed since last deploy | Revoke script does | Default |
|---|---|---|
| A role's grant on a view (grantee removed in UC, group remapped, view now needs review) | `REVOKE SELECT ON <view> FROM <role>` | always |
| A group from a role (no longer mapped, or no longer has any granted view) | `ALTER ROLE <role> DROP MEMBER <group>` | always |
| A view no longer deployed (dropped in UC, or now needs review) | `DROP VIEW`, dependents first | only with `--drop-removed-objects`, else written commented out |
| A role no longer used | `DROP ROLE` | only with `--drop-removed-objects`, else written commented out |

Design choices, and their risks:

* **The diff only touches what this toolkit created.** It compares two
  manifests, not the live endpoint. A grant, member, view or role someone
  added by hand is never in a manifest, so it is never revoked. The flip
  side: hand-made drift is **not detected**. Audit `sys.database_permissions`
  and `sys.database_role_members` separately if that matters.
* **The manifest must reflect what was actually deployed.** Only keep
  `deployed_state.json` from a run whose scripts all succeeded; the pipeline
  enforces this. If you diff against a manifest that was never deployed,
  revocations can be missed. If the manifest is lost, revocations can't be
  computed. Recover by comparing the endpoint's `sys.database_permissions`
  against the new `fabric_view_grants.csv` by hand.
* **Revokes cut access; drops are cleanup.** That's why drops are opt-in.
  `DROP ROLE` fails if someone added members to the role by hand, and the
  pipeline stops there.
* Every revoke statement is guarded (`OBJECT_ID`, `sys.database_role_members`),
  so re-running a revoke script is safe.

## Running it

```bash
python -m dbx_fabric_security.cli generate-fabric-sql \
  --views out/databricks-extract/extracted_views.sql \
  --grants out/databricks-extract/extracted_grants.csv \
  --table-columns out/databricks-extract/extracted_table_columns.json \
  --role-mapping path/to/ad_group_to_fabric_role.csv \
  --admin-role super_business_admin \
  --admin-schema sec_admin \
  --out-dir out/fabric-sql
```

On every run after the first, add
`--previous-state <last deployed run>/fabric_sql/deployed_state.json`
(and optionally `--drop-removed-objects`).

Add `--strict` in a pipeline gate. It exits non-zero if any view needs
review, any grantee is unmapped, or any role merges groups with different
access.

Run `<catalog>__revoke.sql` (if present) and then `<catalog>__deploy.sql` with a tool that honours `GO`, such as sqlcmd,
SSMS or VS Code mssql, against the mirrored item's SQL analytics endpoint.
Use an identity with permission to create schemas, views and roles there,
typically a workspace Admin or Member.

### Azure DevOps pipeline

[`pipelines/azure-pipelines-fabric-sql-endpoint.yml`](../pipelines/azure-pipelines-fabric-sql-endpoint.yml)
automates the whole cycle:

1. **Generate**: runs the unit tests and downloads `deployed_state.json` from
   the latest successful run of this pipeline on the same branch. It then runs
   `generate-fabric-sql --previous-state ... --strict` and publishes the
   scripts as artifact `fabric-sql-scripts`, even when `--strict` fails, so
   the report can be reviewed.
2. **Deploy**: a deployment job on environment `fabric-security-prod`, so
   configure a required-reviewer approval there. It installs go-sqlcmd and
   logs in through the Azure service connection. For each catalog it runs
   `__revoke.sql`, then `__deploy.sql`, with `sqlcmd -b`, so the first error
   stops the run. A catalog with no entry in the endpoints JSON (see
   [`pipelines/fabric_sql_endpoints.sample.json`](../pipelines/fabric_sql_endpoints.sample.json))
   fails the deploy before anything runs.
3. When every script succeeds, it publishes the new `deployed_state.json`
   as artifact `fabric-sql-deployed-state` for the next run.

Parameters:

| Parameter | Default | Notes |
|---|---|---|
| `extractSource` | `databricksPipeline` | Or `localFile` with repo paths in the variable group. |
| `azureServiceConnection` | `fabric-sql-deployer` | Its service principal needs create and grant rights on each mirrored item's SQL endpoint. |
| `firstRun` | `false` | Set `true` once, for the first deployment only. Otherwise a missing previous state **fails** the run instead of silently skipping revocations. |
| `dropRemovedObjects` | `false` | Passes `--drop-removed-objects`. |
| `strict` | `true` | Fails Generate on any view needing review, unmapped grantee or role merging different access. |

Pipeline risks:

* `runVersion: latestFromBranch` takes the latest **successful** run. Say a
  run's Deploy succeeds but the run is then marked failed or cancelled. The
  next run diffs against the older state, so revocations for objects added
  in between can be missed. Deploy is the last stage on purpose. Don't add
  failure-prone stages after it.
* Unverified on a hosted agent: installing `sqlcmd` from
  packages.microsoft.com, and `--authentication-method ActiveDirectoryDefault`
  picking up the AzureCLI@2 login. Test the pipeline against a non-production
  mirror first.

## Risks and things to verify before go-live

These assumptions could not be checked against current Microsoft Learn pages
from the environment this was written in. **Verify each one in your tenant.**

| # | Assumption | How to verify | If wrong |
|---|---|---|---|
| 1 | The mirrored item's SQL analytics endpoint accepts `CREATE SCHEMA`, `CREATE OR ALTER VIEW`, `CREATE ROLE`, `ALTER ROLE ... ADD MEMBER` (Entra group) and `GRANT SELECT ON <view>`. | Run the generated script on a test mirror. | Run the views and roles against a Fabric Warehouse in the same workspace, using three-part names. Retest #2, since ownership chaining across items is not assumed. |
| 2 | **Ownership chaining**: a user with `SELECT` on a view, and no permission on its base table, can query the view. | As a test user who is only in one role, `SELECT` from the view (should work) and from the base table (should fail). | The design does not work. The user would need base-table access, which defeats the views. |
| 3 | Users have **no** path around the views. | Share the mirrored item with users at **Read** (connect) only: no ReadData, no ReadAll, no workspace role. A workspace Viewer or higher role, or ReadData/ReadAll, gives table or OneLake access. As a test user, confirm the base table and its OneLake files are both denied. | Data leak. Remove the extra permissions. |
| 4 | Turning on OneLake security on the mirrored item does not change #2 or #3. | Leave OneLake security off unless needed. If it is on, retest #2 and #3 in both delegated and user-identity endpoint modes. | Views may stop returning data, or the bypass may reappear. |
| 5 | `ALTER ROLE ... ADD MEMBER [name]` resolves the Entra group by the name in `fabric_principal`/`ad_group`. | Check `sys.database_role_members` after deployment, and test with one member of each group. | Put the Entra display name or UPN Fabric expects in `fabric_principal`. |
| 6 | Mirrored tables keep the Unity Catalog schema and table names. | Compare the endpoint's `INFORMATION_SCHEMA.TABLES` with UC. | View DDL will fail with invalid object names. Adjust the names. |

Known limitations of this path:

* **T-SQL only.** The views and grants protect the SQL analytics endpoint and
  anything that queries it, such as Power BI in DirectQuery mode. They do not
  protect Spark notebooks or direct OneLake readers, which is why #3 matters.
  Power BI Direct Lake over a view falls back to DirectQuery.
* **Revocation depends on the manifest.** Revocations are only computed
  with `--previous-state`, and only for objects this toolkit deployed (see
  "Revoking access that is no longer wanted"). Hand-made grants are
  neither revoked nor detected.
* **Native UC row filters and column masks** (`ALTER TABLE ... SET ROW
  FILTER/MASK`) are out of scope, as in the rest of the toolkit. Tables with
  them are also excluded from mirroring, so views on them fail at creation.
* **Mirroring lag.** Views reflect mirrored data, which can trail Databricks.
* **Schema drift.** A dropped or renamed column in Databricks breaks views
  that use it, at query time. `SELECT *` views also need re-creating after
  added columns. Re-run the script after schema changes.
* **Identity-based views** need manual rewrites, for example
  `current_user()` → `SUSER_SNAME()`, which returns the Entra UPN. Test
  these with real users before granting.
