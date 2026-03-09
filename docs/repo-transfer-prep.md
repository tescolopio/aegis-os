# Repository Transfer Prep

Updated: 2026-03-09
Purpose: prepare Aegis OS for transfer from the current personal GitHub namespace to 3D Tech Solutions LLC without losing track of documentation, branding work, or internal investor materials.

## Decision

Current founder intent is that everything under `docs/internal/` remains local-only.

That means:

- internal marketing, funding, outreach, and draft materials should not be committed to this repository,
- the transfer effort should treat `docs/internal/` as private founder working material,
- any sharing of those materials should happen outside this repo unless the founder explicitly changes that decision later.

## Current State

The repository is mid-stream in two different kinds of work:

- product and Phase 2 development changes already present in the working tree,
- documentation and ownership migration updates prepared for transfer and fundraising support.

This means the development team should not treat the current working tree as a small isolated patch. It contains substantial unrelated engineering work in addition to the documentation prep.

## Important Constraint

The investor and outreach materials created for this effort live under `docs/internal/`.

That path is explicitly ignored by git in `.gitignore`:

```gitignore
docs/internal/
```

As a result, the following files will **not** be committed or pushed unless the team deliberately changes the repo layout or git ignore rules:

- `docs/internal/presentations/investor-brief.md`
- `docs/internal/drafts/operating-metrics-template.md`
- `docs/internal/drafts/commercial-pipeline-template.md`
- `docs/internal/drafts/design-partner-case-study-template.md`
- `docs/internal/drafts/outreach-content-template.md`
- `docs/internal/funding-questions.md`
- `docs/internal/combined-questions.md`

## What Has Been Prepared

### Ownership and branding cleanup

User-facing repo references were updated toward `3D-Tech-Solutions`, including:

- README clone and maintainer references
- changelog compare and release links
- deployment guide image namespace examples

### Internal fundraising support package

Prepared locally under `docs/internal/`:

- evidence-backed answers to Aegis funding questions
- evidence-backed answers to combined Aegis + Code Scalpel questions
- investor brief
- templates for metrics, pipeline, case studies, and outreach

### Tracked handoff file

This file is intentionally outside `docs/internal/` so the team can commit it as part of transfer prep.

## Handling Options For `docs/internal/`

The options below are listed for completeness, but the active decision right now is **Option 1**.

Choose one of these before commit.

### Option 1: Keep internal materials local-only

This is the currently selected approach.

Use this if the investor docs should remain off-repo.

What to do:

1. Leave `.gitignore` unchanged.
2. Do not attempt to commit `docs/internal/`.
3. Copy the internal files into a private company repo, private knowledge base, or secured document workspace.

Best when:

- fundraising content is confidential,
- the public or shared engineering repo should stay product-only,
- outreach assets will be owned by business ops rather than engineering.

### Option 2: Move selected files into a tracked private-docs location in this repo

Use this if the repository itself is private and you want the investor work versioned.

Suggested destination:

- `docs/private/`
- `docs/fundraising/`
- `ops/fundraising/`

What to do:

1. Create the chosen tracked directory.
2. Move only the files you want versioned.
3. Keep the most sensitive drafts out if needed.

Best when:

- you want a single-source-of-truth repo,
- the team reviewing the transfer also needs the fundraising materials,
- the repository will remain private after transfer.

### Option 3: Selectively unignore only the investor package

Use this only if the team wants to keep the existing folder structure.

What to do:

1. Update `.gitignore` to stop ignoring specific files under `docs/internal/`.
2. Add only the approved files.
3. Confirm no scratch notes or sensitive local-only artifacts are accidentally included.

Best when:

- the current internal layout is already the desired permanent location,
- the team is comfortable reviewing ignore rules carefully.

## Recommended Transfer Sequence

1. Decide whether `docs/internal/` stays local-only or becomes tracked.
2. Split the current working tree into logical commits instead of one large mixed commit.
3. Land the branding and ownership reference updates first.
4. Land any approved tracked transfer-prep docs second.
5. Keep unrelated Phase 2 engineering changes separate from transfer-prep commits.
6. Transfer the GitHub repository to `3D-Tech-Solutions`.
7. Update package/image namespaces, branch protections, repo URLs, and release automation after transfer.

## Suggested Commit Grouping

### Commit group A: branding and ownership migration

Intended scope:

- `README.md`
- `CHANGELOG.md`
- `docs/deployment-guide.md`

### Commit group B: tracked transfer-prep docs

Intended scope:

- `docs/repo-transfer-prep.md`
- any investor or metrics files moved out of `docs/internal/`, if approved

### Commit group C: Phase 2 engineering work

Intended scope:

- the substantial existing code, test, docs, and policy changes already present in the working tree

This group should be reviewed independently because it is much larger and materially changes runtime behavior.

## Post-Transfer Checklist

- GitHub repo path changed to `3D-Tech-Solutions/aegis-os`
- README badges and links verified
- GHCR image references verified
- release compare links verified
- branch protection and default branch settings recreated
- secrets and automation revalidated under org ownership
- package namespaces checked
- documentation references to `tescolopio` re-scanned

## Internal Package Index

If the team wants to preserve the investor package before transfer, the prepared local files are:

- `docs/internal/funding-questions.md`
- `docs/internal/combined-questions.md`
- `docs/internal/presentations/investor-brief.md`
- `docs/internal/drafts/operating-metrics-template.md`
- `docs/internal/drafts/commercial-pipeline-template.md`
- `docs/internal/drafts/design-partner-case-study-template.md`
- `docs/internal/drafts/outreach-content-template.md`

## Recommendation

Given the current founder preference, the path for this repository is:

1. keep `docs/internal/` local-only,
2. commit the ownership migration changes and this tracked handoff doc,
3. move the investor package into a separate private company repo or workspace managed by 3D Tech Solutions LLC.

That keeps fundraising and marketing materials private while still letting the development team transfer and clean up the product repository.