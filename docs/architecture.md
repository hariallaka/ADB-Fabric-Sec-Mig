# Architecture

## End-to-end pipeline

```mermaid
flowchart TD
    A["Databricks / Unity Catalog\nView Definitions (CLS + RLS)"] --> B["Security Extraction Utility\n(view_parser.py, sqlglot-based)"]
    AGS["AGS\n(AD Group Sync — authoritative identity source)"] --> B
    B --> C["JSON / CSV Security Model\n(view_security_definitions,\ncls_entitlements, rls_entitlements)"]
    C --> D["Translator\n(cls_translator.py, rls_translator.py,\nrole_builder.py)"]
    D --> E["Fabric Data Access Role payloads\n+ AGS→AD Group→Fabric Role mapping"]
    E --> F["Azure DevOps Pipeline\nExtract → Translate → Validate →\nApproval Gate → Deploy → Report"]
    F --> G["Fabric REST API\nItem Data Access Roles"]
    G --> H["Fabric OneLake Security Roles"]
    H --> I["OneLake Shortcut / UCM Data Objects\n(Lakehouse Tables)"]
```

## Security role mapping (scope item 3)

```mermaid
flowchart LR
    AGS["AGS group\n(e.g. 'Finance Data Readers')"] --> ADG["AD Group\n(Entra ID, object id)"]
    ADG --> ROLE["OneLake Security Role\n(role_<table>_<group>)"]
    ROLE --> OBJ["OneLake Shortcut / UCM Data Object\n(Lakehouse table, e.g. sec.hr.employee)"]
    ROLE -.column rule.-> COL["Permitted / masked columns"]
    ROLE -.row rule.-> ROW["Row filter predicate"]
```

Group membership management, role creation, and the relationship between
Fabric roles and OneLake objects are all driven from the same extraction
output: one Fabric role is created per **(table, AD group)** pair found in
the Databricks view definitions, carrying whatever column and row rules
were derived for that pairing. AGS remains authoritative for group
membership; this toolkit never creates, edits, or deletes AD groups or AGS
records -- it only reads the AGS export to resolve group names to Entra
object ids for role `members` payloads.

## Component responsibilities

| Component | Responsibility | Source |
|---|---|---|
| Security Extraction Utility | Parse Databricks view DDL, extract column lineage, CLS masks, RLS predicates, and flag unsupported constructs | `src/dbx_fabric_security/extractor/` |
| Translator | Convert extracted constructs into Fabric-shaped CLS/RLS entitlements and merged Data Access Role payloads | `src/dbx_fabric_security/translator/` |
| Role Mapper | Join AGS export data to generated roles for the AGS → AD Group → Fabric Role → OneLake object report | `src/dbx_fabric_security/mapping/` |
| Fabric API Client | Thin REST wrapper (dry-run by default) around the Fabric Item Data Access Roles API | `src/dbx_fabric_security/fabric_api/` |
| CLI | Orchestrates extract → translate → map-roles → deploy as a single command or discrete steps | `src/dbx_fabric_security/cli.py` |
| Azure DevOps Pipeline | Runs the CLI stages with a manual approval gate before any live deploy | `pipelines/azure-pipelines-security-migration.yml` |
