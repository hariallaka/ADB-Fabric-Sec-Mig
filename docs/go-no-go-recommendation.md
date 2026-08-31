# Spike Outcome: Go / No-Go Recommendation

## Recommendation: **Conditional Go**

Automated translation of Databricks Unity Catalog view-based CLS/RLS into
Microsoft Fabric OneLake security roles is **technically viable** and was
demonstrated end-to-end in this spike's proof of concept: extraction,
translation (including the derived-column assumption), AGS-to-Fabric-role
mapping, and a dry-run automated deployment all work against representative
view patterns, with 19/19 automated tests passing (see
[poc-findings.md](./poc-findings.md)).

Proceeding to a production build is recommended **conditional on** closing
three gaps before implementation scope is finalized:

1. **Confirm which Databricks security pattern the target estate actually
   uses.** This toolkit's extraction covers *view-embedded* CLS/RLS (the
   `CASE WHEN is_account_group_member(...) ...` pattern named in the
   ticket). It does **not** read native Unity Catalog row filters/column
   masks (`ALTER TABLE ... SET ROW FILTER/MASK`), which is the more common
   pattern in estates onboarded after UC's native RLS/CLS went GA. This is
   the single largest scope risk of the three — it determines whether a
   second extraction path needs to be built before this approach covers the
   real environment at all. **Run `SHOW ROW FILTERS`/`SHOW COLUMN MASKS`
   against a representative sample of production catalogs before
   finalizing implementation scope** (see
   [limitations.md](./limitations.md#native-unity-catalog-row-filters--column-masks-not-covered)).
2. **Validate the Fabric Item Data Access Roles API schema against a live
   tenant.** This spike's role payloads (`role_builder.py`) are a
   best-effort mapping to a preview API whose exact field names/grammar
   were not confirmed against a live call in this spike (no Fabric tenant
   credentials were in scope). This is a short (hours, not days)
   validation task, isolated to one module — it does not put the rest of
   the design at risk, but it must happen before any code here is pointed
   at production.
3. **Decide the production posture on nested and complex views** (see
   [limitations.md](./limitations.md)). These are *detected*, not silently
   mis-translated, but a decision is needed on whether to (a) build the
   nested-view composition pass, (b) require source views to be
   flattened/simplified before onboarding to this pipeline, or (c) route
   flagged views to a permanent manual-translation track. This is a scope
   and process decision, not a technical blocker.

Neither gap invalidates the architecture or the translation logic
demonstrated; both are naturally scoped next steps rather than reasons to
stop.

## Why Go

- **Required Fabric APIs identified.** The Item Data Access Roles API is
  the correct provisioning target and matches the ticket's own
  `OneLake Security Role` language; no missing capability was found that
  would block the approach outright.
- **AGS remains authoritative.** The design never writes to AGS or AD
  groups; it only reads exports, satisfying a hard constraint from the
  ticket's scope and success criteria.
- **The one named design risk (derived columns) is solved and tested.**
  The exact example from the ticket (`a * b AS c`) was implemented and
  passes as a unit test, not just a documented intention.
- **Automation is real, not aspirational.** A working CLI
  (`extract | translate | map-roles | deploy`) and an Azure DevOps pipeline
  with a manual approval gate before any live Fabric call were both built
  and exercised in this spike, not just designed on paper.
- **Failure modes degrade safely.** Unrecognized SQL constructs are flagged
  for manual review rather than silently mis-translated; unresolved AD
  groups block deployment rather than deploying with a missing member;
  deploys default to dry-run and never touch a manually-authored Fabric
  role.

## Why not an unconditional Go

- **This is the biggest open question, ahead of the API risk below:**
  extraction was proven against the view-embedded CLS/RLS pattern the
  ticket named, but not validated against a real catalog to confirm that
  pattern (rather than native UC row filters/column masks) is what's
  actually deployed. If the real estate leans native, extraction coverage
  today is closer to zero than to "done" for those tables, regardless of
  how well translation and role-building work downstream.
- The Fabric API this design depends on most heavily (Data Access Roles)
  was in public preview and unvalidated against a live tenant in this
  spike — a schema change there is the single largest source of rework
  risk on the Fabric side, and it hasn't been retired yet.
- Nested and complex views are real limitations, not edge cases likely to
  be rare in a mature Unity Catalog estate; the production scope estimate
  should assume a non-trivial fraction of views will need one of the three
  postures above, not that they'll be a rounding error.

## Suggested next steps

1. Run `SHOW ROW FILTERS` / `SHOW COLUMN MASKS` (or query
   `information_schema.table_row_filters`/`column_masks`) against a
   representative sample of production catalogs to settle gap §1 — this
   determines whether a second extraction path is required before scope is
   finalized.
2. Run the Fabric API validation pass described in §2 against a
   non-production Fabric workspace.
3. Inventory a representative sample of real production Databricks views
   (not just the 8 synthetic fixtures used here) and re-run this toolkit's
   `extract` / `extract-databricks` command against them to get a
   real-world unsupported-construct rate — this sizes the nested/complex-view
   decision in §3 with data instead of a guess.
4. Feed all three outputs into the UCM Solution Architecture Document as
   inputs to a scoped implementation plan (with the conditions above as
   explicit prerequisites, not implementation-time surprises).
