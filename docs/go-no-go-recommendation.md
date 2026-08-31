# Spike Outcome: Go / No-Go Recommendation

## Recommendation: **Conditional Go**

Automated translation of Databricks Unity Catalog view-based access into
Microsoft Fabric OneLake security roles is **technically viable** and was
demonstrated end-to-end in this spike's proof of concept: extraction (Unity
Catalog SELECT grants, principal object ids via SCIM, and view shape),
translation (including the derived-column assumption and verbatim
WHERE-clause reproduction, including OR-joined predicates), AD
Group/principal-to-Fabric-role mapping, and a dry-run automated deployment
all work against representative view patterns, with 37/37 automated tests
passing (see [poc-findings.md](./poc-findings.md)).

The model settled on is deliberately simple: a view's grantees come from
Unity Catalog's actual `SELECT` grants (queried directly, never inferred
from SQL), and the view's SQL is used only to work out what data that grant
covers — the flattened source columns for CLS, and the WHERE clause
verbatim for RLS. That simplicity is itself a feasibility point in favor of
Go: there is very little translation logic that can be subtly wrong,
because there is very little translation logic, period.

Proceeding to a production build is recommended **conditional on** closing
three gaps before implementation scope is finalized:

1. **Confirm the target estate doesn't rely on native Unity Catalog row
   filters/column masks** (`ALTER TABLE ... SET ROW FILTER/MASK`). This
   toolkit's security model is entirely view-based (a view's SELECT grant
   plus its SQL shape); it does not read native row filters/masks attached
   directly to tables, which live in a different system table entirely and
   are invisible to this toolkit. **Run `SHOW ROW FILTERS`/`SHOW COLUMN
   MASKS` against a representative sample of production catalogs before
   finalizing implementation scope** (see
   [limitations.md](./limitations.md#native-unity-catalog-row-filters--column-masks-not-covered)).
2. **Validate the Fabric Item Data Access Roles API schema against a live
   tenant.** This spike's role payloads (`role_builder.py`) are a
   best-effort mapping to a preview API whose exact field names/grammar
   were not confirmed against a live call in this spike (no Fabric tenant
   credentials were in scope). This also covers confirming that Fabric's
   row-filter expression grammar accepts the Databricks-SQL predicates this
   toolkit reproduces verbatim. Short (hours, not days), isolated to one
   module.
3. **Decide the production posture on nested and complex views** (see
   [limitations.md](./limitations.md)). These are *detected*, not silently
   mis-translated, but a decision is needed on whether to (a) build the
   nested-view grant/filter composition pass, (b) require source views to
   be flattened/simplified before onboarding to this pipeline, or (c) route
   flagged views to a permanent manual-translation track.

Neither gap invalidates the architecture or the translation logic
demonstrated; both are naturally scoped next steps rather than reasons to
stop.

## Why Go

- **Required Fabric APIs identified.** The Item Data Access Roles API is
  the correct provisioning target and matches the ticket's own
  `OneLake Security Role` language.
- **Identity stays read-only and single-sourced.** The design never writes
  to Databricks/Entra group membership; it only reads Unity Catalog grants
  and SCIM directory data directly, with no separate identity export to
  keep in sync. The one write it performs (`grant-catalog-access`) is a
  one-time, admin-run catalog access grant, not an identity change.
- **Access is read from the real source of truth.** Grants come from Unity
  Catalog's own `SELECT` privilege data, not guessed from SQL patterns —
  removing an entire category of "did we parse the identity check
  correctly" risk that an earlier iteration of this design carried.
- **The one named design risk (derived columns) is solved and tested.**
  The exact example from the ticket (`a * b AS c`) was implemented and
  passes as a unit test, not just a documented intention.
- **The OR-clause requirement is met by construction, not by a special
  case.** WHERE clauses are never decomposed — they're captured and
  reproduced verbatim — so `OR`, `AND`, and arbitrary nesting all work
  without dedicated handling to get wrong. Tested directly, including a
  nested `(A AND B) OR C` case.
- **Automation is real, not aspirational.** A working CLI
  (`extract | extract-databricks | translate | map-roles | deploy`) and two
  Azure DevOps pipelines (Databricks-side extraction, Fabric-side
  translate/deploy, chained via a pipeline artifact) with a manual approval
  gate before any live Fabric call were both built and exercised in this
  spike, not just designed on paper.
- **Failure modes degrade safely.** Unrecognized SQL constructs (joins,
  nested views, `SELECT *`) are flagged for manual review rather than
  silently mis-translated; a grantee whose Azure AD object id can't be
  resolved blocks deployment rather than deploying with a missing member;
  deploys default to dry-run and never touch a manually-authored Fabric
  role.

## Why not an unconditional Go

- **This is the biggest open question, ahead of the API risk below:**
  extraction was proven against Unity Catalog's view-grant model, but not
  validated against a real catalog to confirm the target estate doesn't
  also lean on native row filters/column masks, which this toolkit cannot
  see at all. If it does, coverage for those tables is zero regardless of
  how well the view-based translation works.
- The Fabric API this design depends on most heavily (Data Access Roles)
  was in public preview and unvalidated against a live tenant in this
  spike — a schema change there, or a row-filter grammar that rejects some
  Databricks-SQL construct this toolkit reproduces verbatim, is the largest
  source of rework risk on the Fabric side.
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
   non-production Fabric workspace, including a spot-check that its
   row-filter grammar accepts a representative sample of real WHERE
   clauses from the target estate.
3. Inventory a representative sample of real production Databricks views
   (not just the 7 synthetic fixtures used here) and re-run this toolkit's
   `extract` / `extract-databricks` command against them to get a
   real-world unsupported-construct rate — this sizes the nested/complex-view
   decision in §3 with data instead of a guess.
4. Feed all three outputs into the UCM Solution Architecture Document as
   inputs to a scoped implementation plan (with the conditions above as
   explicit prerequisites, not implementation-time surprises).
