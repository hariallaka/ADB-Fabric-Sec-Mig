# Architecture

## End-to-end pipeline

```mermaid
flowchart TD
    A["Databricks / Unity Catalog\nView Definitions (SELECT + WHERE)"] --> B["Security Extraction Utility\n(view_parser.py, sqlglot-based)"]
    G0["Unity Catalog SELECT Grants\n(information_schema.table_privileges)"] --> B
    AGS["AGS\n(AD Group Sync — authoritative identity source)"] --> D
    B --> C["JSON / CSV Security Model\n(view_security_definitions,\ncls_entitlements, rls_entitlements)"]
    C --> D["Translator\n(cls_translator.py, rls_translator.py,\nrole_builder.py)"]
    D --> E["Fabric Data Access Role payloads\n+ AGS→AD Group→Fabric Role mapping"]
    E --> F["Azure DevOps Pipeline\nExtract → Translate → Validate →\nApproval Gate → Deploy → Report"]
    F --> G["Fabric REST API\nItem Data Access Roles"]
    G --> H["Fabric OneLake Security Roles"]
    H --> I["OneLake Shortcut / UCM Data Objects\n(Lakehouse Tables)"]
```

Access (who) and shape (what data) are extracted as two independent
inputs and joined by view name — a view's grantees come from Unity
Catalog's actual `SELECT` grants, never from parsing its SQL; the SQL is
only used to work out which physical columns and which row predicate that
grant covers. See `docs/technical-assessment.md` §1 for why this replaced
an earlier SQL-pattern-matching approach.

## Security role mapping (scope item 3)

```mermaid
flowchart LR
    AGS["AGS group\n(e.g. 'Finance Data Readers')"] --> ADG["AD Group / principal\n(Entra ID, object id)"]
    ADG --> ROLE["OneLake Security Role\n(role_<table>_<principal>)"]
    ROLE --> OBJ["OneLake Shortcut / UCM Data Object\n(Lakehouse table, e.g. sec.hr.employee)"]
    ROLE -.column rule.-> COL["Flattened source columns\n(derived-column aliases excluded)"]
    ROLE -.row rule.-> ROW["Row filter predicate\n(view's WHERE clause, verbatim)"]
```

Group membership management, role creation, and the relationship between
Fabric roles and OneLake objects are all driven from the same extraction
output: one Fabric role is created per **(table, principal)** pair found in
the Databricks view definitions, carrying whatever column list and row
filter were derived for that pairing. AGS remains authoritative for group
membership; this toolkit never creates, edits, or deletes AD groups or AGS
records -- it only reads the AGS export to resolve principal names to Entra
object ids for role `members` payloads.

## Pipeline split (interim) vs. target state

```mermaid
flowchart TD
    subgraph DBXSIDE["Databricks-side (today: Databricks-scoped identity)"]
        direction TB
        DBX["azure-pipelines-databricks-extract.yml\n(extract-databricks)"]
    end
    subgraph FABSIDE["Fabric-side (today: Fabric-scoped identity)"]
        direction TB
        FAB["azure-pipelines-security-migration.yml\n(translate -> validate -> approve -> deploy)"]
    end
    DBX -- "extracted-views artifact\n(pipeline resource)" --> FAB

    TARGET["Target state: one Azure DevOps pipeline,\none Azure AD identity with both\nDatabricks + Fabric RBAC (see README)"]
    DBXSIDE -.consolidates into.-> TARGET
    FABSIDE -.consolidates into.-> TARGET
```

Today the two pipelines run under separate identities/service connections so
each side can be permissioned minimally and independently (see README.md,
"RBAC / permissions required"). Neither the extraction code nor the
translate/deploy code changes to support the target state -- consolidating
onto one Azure AD application that holds both sets of grants, and one
pipeline (or one pipeline with two stages using that identity), is purely a
credentials/pipeline-wiring change.

## Component responsibilities

| Component | Responsibility | Source |
|---|---|---|
| Security Extraction Utility | Parse Databricks view DDL (flattened columns, verbatim WHERE clause), read Unity Catalog SELECT grants, and flag unsupported constructs | `src/dbx_fabric_security/extractor/` |
| Translator | Cross-product grantees × flattened columns (CLS) and grantees × WHERE clause (RLS) into Fabric-shaped entitlements and merged Data Access Role payloads | `src/dbx_fabric_security/translator/` |
| Role Mapper | Join AGS export data to generated roles for the AGS → AD Group → Fabric Role → OneLake object report | `src/dbx_fabric_security/mapping/` |
| Fabric API Client | Thin REST wrapper (dry-run by default) around the Fabric Item Data Access Roles API | `src/dbx_fabric_security/fabric_api/` |
| CLI | Orchestrates extract → translate → map-roles → deploy as a single command or discrete steps | `src/dbx_fabric_security/cli.py` |
| Azure DevOps Pipeline | Runs the CLI stages with a manual approval gate before any live deploy | `pipelines/azure-pipelines-security-migration.yml` |
