---
title: "fix: release merge-to-main auto-merges with a scoped admin token"
type: fix
status: active
date: 2026-06-19
---

# fix: release merge-to-main auto-merges with a scoped admin token

## Overview
The `merge-to-main` job in `.github/workflows/release.yml` opens a `develop`→`main` PR and runs
`gh pr merge --merge --admin`, but it authenticates with the default `github.token`
(`github-actions[bot]`). That identity is not a repo admin and not a bypass actor, so it cannot
override `main`'s protection and the job fails loudly ("at least 1 approving review is required; 2 of 2
required status checks are expected") — leaving a maintainer to merge the release PR by hand
(as happened for v0.21.0, PR #208).

Fix: run **only the `merge-to-main` job** with a scoped admin-capable token (a GitHub App
installation token, preferred; an admin PAT as fallback). No branch-protection change is required.

## Problem Frame
Release completion should be hands-off after `gh workflow run release.yml`. Today the final step
(`develop`→`main`) always requires a human admin merge. Observed on every recent release; the
workflow comment already documents this as the intended "fail loudly, maintainer merges" fallback —
this plan finishes the auto-merge path the comment anticipates.

## Root Cause (verified 2026-06-19)
`main` protection:
- **Classic branch protection**: `required_approving_review_count: 1`; `required_status_checks:
  [build-macos, build-linux]`, `strict: true`; `enforce_admins: false`; `bypass_pull_request_allowances:
  none`.
- **Ruleset "Protect main"** (id 17173359): rules `pull_request`, `deletion`, `non_fast_forward`;
  **`bypass_actors: []`**. The `pull_request` rule only requires that a PR exists — it is satisfied by
  the bot creating the PR, so the ruleset is **not** the blocker.

The binding requirements (1 review + 2 checks) come from **classic protection**, which only **repo
admins** can bypass (because `enforce_admins: false`). `github-actions[bot]` is not an admin →
`--admin` override is rejected. A repo-admin identity (proven: a maintainer's `gh pr merge --admin`
merged PR #208 with no settings change) bypasses both the review and the checks.

## Key Technical Decisions
- **Scoped admin token, not a global protection change.** Grant the bypass to one job, not to all
  workflows or by weakening `main`. Blast radius = the release `merge-to-main` job only.
- **GitHub App token preferred over a personal PAT.** An App installation token is minted per-run
  (no long-lived secret), is not tied to a person who may leave, and is auditable as its own actor.
  A fine-grained admin PAT is the fallback if standing up an App is not desired now.
- **No branch-protection / ruleset edit needed.** Because repo-admin already bypasses (classic
  `enforce_admins: false`), the token identity simply needs the admin permission level. Avoids
  widening `main`'s bypass surface.
- **Bypassing the PR's `build-macos`/`build-linux` checks is acceptable for the release merge** —
  `release-commit` already built all artifacts and ran `swift build`/`swift test`, and `develop` CI
  passed before the release. The release PR is a fast-forward-style promotion of already-verified code.

## Open Questions
### Resolved during planning
- Which protection layer blocks the bot? → Classic protection (review + checks); the ruleset only
  needs a PR to exist.
- Does an admin identity bypass without settings changes? → Yes (manual admin merge of PR #208 proved
  it).

### Deferred to implementation
- **Does a GitHub App token satisfy `gh pr merge --admin`?** The override requires the actor to be
  treated as repo admin. Grant the App `administration: write` (plus `contents: write`,
  `pull_requests: write`) and **verify** with a dry-run (Unit 4). If the App is not honored as admin
  for the override, fall back to the admin PAT (known to work).
- Final secret names (e.g. `RELEASE_APP_ID` + `RELEASE_APP_PRIVATE_KEY`, or `RELEASE_MERGE_TOKEN`).

## Implementation Units

- [ ] **Unit 1: Provision the bot identity + token (manual, maintainer)**

**Goal:** A scoped admin-capable credential available to CI.

**Approach (preferred — GitHub App):**
- Create/confirm an org GitHub App (e.g. "Virgil Release Bot") with repository permissions
  **Administration: read/write**, **Contents: read/write**, **Pull requests: read/write**.
- Install it on `VirgilSecurity/virgil-crypto-c`.
- Store `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` as repo (or org) Actions secrets.

**Fallback (admin PAT):** create a fine-grained PAT owned by a repo admin (or a machine admin
account) scoped to this repo with Contents RW + Pull requests RW + Administration RW; store as
`RELEASE_MERGE_TOKEN`.

**Verification:** secrets present in repo/org settings.

- [x] **Unit 2: Wire the token into the `merge-to-main` job**

**Goal:** The merge step authenticates as the admin identity, nothing else changes.

**Files:**
- Modify: `.github/workflows/release.yml` (the `merge-to-main` job only)

**Approach (GitHub App):** add a token-mint step and use its output as `GH_TOKEN`:
```yaml
  merge-to-main:
    ...
    steps:
      - uses: actions/create-github-app-token@v2
        id: app-token
        with:
          app-id: ${{ secrets.RELEASE_APP_ID }}
          private-key: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}
      - uses: actions/checkout@v6
      - name: Merge release branch to main
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}   # was: ${{ github.token }}
          BRANCH: ${{ inputs.branch }}
          VERSION: ${{ inputs.version }}
        run: |
          ... existing gh pr list/create/merge --admin ...
```
**Fallback (PAT):** set `GH_TOKEN: ${{ secrets.RELEASE_MERGE_TOKEN }}` on the existing step; no mint step.

**Patterns to follow:** the existing `merge-to-main` job; keep `needs`, `if`, and the create-or-locate
PR logic unchanged. Do not change other jobs (they keep `github.token`).

**Test scenarios:**
- Integration (dry-run, Unit 4): with a no-op/test version, the job creates the PR and `gh pr merge
  --admin` succeeds (exit 0) and `main` advances.
- Error path: if the token lacks admin override, the job still fails loudly with the same clear
  message (no silent success) — preserve the existing `set -euo pipefail` + `::error::` behavior.

**Verification:** the merge step exits 0 and `origin/main` includes the release commit/tag.

- [ ] **Unit 3: Confirm no branch-protection change is needed (document)**

**Goal:** Avoid widening `main`'s bypass surface; record the rationale.

**Approach:** verify the App/PAT identity has admin (so classic `enforce_admins:false` bypass applies).
Only if the App is *not* honored as admin for the override, add it to classic
`bypass_pull_request_allowances` and/or the ruleset `bypass_actors` as a documented last resort — and
note the tradeoff. Capture the final decision in the PR description.

**Test expectation:** none — config verification only.

- [ ] **Unit 4: Verify end-to-end and add a rollback note**

**Goal:** Prove auto-merge works without a real release, and make reverting trivial.

**Approach:**
- Trigger a **pre-release dry-run** (e.g. `0.21.1-dev.1`) — but note `merge-to-main` is gated to
  production (`if: !contains(version,'-')`). To exercise it without a real bump, either (a) temporarily
  point the job at a throwaway test branch and a scratch base, or (b) accept verification on the next
  real production release with the loud-fail fallback still intact.
- **Rollback:** revert the `merge-to-main` `GH_TOKEN` to `${{ github.token }}` (one-line) — behavior
  returns to loud-fail + manual admin merge. No data risk.

**Verification:** documented rollback; green auto-merge on the verifying run.

## Risks & Dependencies
| Risk | Mitigation |
|------|------------|
| GitHub App token not treated as admin for `--admin` override | Verify in Unit 4; fall back to admin PAT (proven) or add the App to bypass lists (Unit 3) |
| Auto-merge bypasses `main`'s PR status checks | Accepted: `release-commit` already built + tested all artifacts; develop CI passed pre-release |
| Personal PAT expiry / owner offboarding (fallback path) | Prefer the GitHub App; if PAT, use a machine admin account and track expiry |
| Token leakage widening blast radius | Token is mint-per-run (App) or a single repo-scoped secret used only by `merge-to-main`; not exposed to other jobs |

## Scope Boundaries
- Only the `merge-to-main` job changes; all build/publish jobs keep `github.token`.
- Not addressing the PyPI trusted-publisher gap (separate, owner is restoring PyPI access).
- Not consolidating the duplicate classic-protection + ruleset on `main` (worth a follow-up, but out
  of scope here).

## Sources & References
- `.github/workflows/release.yml` — `merge-to-main` job (uses `github.token`, `gh pr merge --admin`).
- `main` protection (verified 2026-06-19): classic review+checks, `enforce_admins:false`; ruleset
  "Protect main" id 17173359 with empty `bypass_actors`.
- Proof admin bypass works with no settings change: manual `gh pr merge 208 --merge --admin` (v0.21.0).
- Related: `docs/solutions/` (release/CI), memory note on release CI fixes.
