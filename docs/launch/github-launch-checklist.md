# OpenBOLA GitHub launch checklist

This is a local, approval-gated runbook. It records what must be checked and
what evidence must be retained; it is not an executable release workflow. No
step below changes GitHub, a remote, a release, or repository history until the
operator has received fresh, explicit approval for that one action.

Target after the pending personal-account transfer: `LeonardSEO/openbola`.
Until the transfer is accepted and each gate is approved separately, keep the
current repository name and remote unchanged. Never copy tokens, cookies,
credentials, or private request material into this document or its evidence.

## 0. Common stop conditions

- STOP if the current owner, default branch, or transfer acceptance cannot be
  read-only verified. Do not guess the destination repository.
- STOP if a command asks for a token on the command line, follows a redirect,
  or proposes a force-push/history rewrite. Force-pushes and history rewrites
  are prohibited for this launch.
- STOP if local checksums, commit SHA, or artifact names differ from the
  reviewed P10 outputs. Abort and preserve the existing remote state.
- Record command output as bounded, redacted evidence. Do not save environment
  dumps, credential-helper output, cookies, or raw target data.

## 1. Verify transfer acceptance and repository identity

Approval needed: none for the read-only preflight; explicit approval is needed
before any rename or transfer mutation.

- Dry-run / preflight (read-only):

  ```bash
  gh repo view --json nameWithOwner,viewerPermission,defaultBranchRef
  gh repo view LeonardSEO/openbola --json nameWithOwner,viewerPermission,defaultBranchRef
  ```

- Confirm in the account UI that the personal-account transfer was accepted,
  then STOP—obtain explicit approval for the rename/transfer operation.
- Mutation example (commented; do not run without approval):

  ```bash
  # STOP—approval required: gh repo rename openbola --yes
  ```

- Post-action verification (read-only):

  ```bash
  gh repo view LeonardSEO/openbola --json nameWithOwner,defaultBranchRef
  ```

Postcondition: the repository is owned by `LeonardSEO`, is named `openbola`,
and the expected default branch is unchanged. If not, abort; do not retry with
force or rewrite history.

## 2. Inspect and, only after approval, update the local remote

Approval needed: explicit approval for changing the local `origin` URL.

- Dry-run / preflight (read-only):

  ```bash
  git remote -v
  git branch --show-current
  git status --short
  ```

- STOP—obtain approval and check the destination in section 1 before applying:

  ```bash
  # git remote set-url origin https://github.com/LeonardSEO/openbola.git
  ```

- Post-action verification (read-only):

  ```bash
  git remote get-url origin
  git ls-remote --symref origin HEAD
  ```

Postcondition: `origin` points to the accepted destination and the remote
default branch is the reviewed branch. Never replace unrelated remotes or
discard local branches.

## 3. Repository topics

Approval needed: explicit approval for the exact topic list.

- Dry-run / preflight (read-only):

  ```bash
  gh repo view LeonardSEO/openbola --json repositoryTopics
  ```

- Agree the final list in the approval record. STOP—obtain approval before
  applying only those topics:

  ```bash
  # gh repo edit LeonardSEO/openbola --add-topic api-security --add-topic bola --add-topic idor
  ```

- Post-action verification (read-only):

  ```bash
  gh repo view LeonardSEO/openbola --json repositoryTopics
  ```

Postcondition: only the approved topics are present. Remove nothing outside
that approved list and abort on an unexpected owner/repository response.

## 4. Private vulnerability-reporting URL

Approval needed: explicit approval for the private reporting URL and its
handling policy. The public security policy remains [SECURITY.md](../../SECURITY.md).

- Dry-run / preflight (read-only):

  ```bash
  gh repo view LeonardSEO/openbola --json nameWithOwner
  rg -n "private|security|report" SECURITY.md
  ```

- STOP—obtain approval for the exact URL and use the GitHub repository Security
  settings UI (or its documented API) only then. Never place the URL, a token,
  or a customer endpoint in this checklist. A commented placeholder is the
  only command form allowed here:

  ```bash
  # STOP—approval required: configure the approved private reporting URL in GitHub Security settings
  ```

- Post-action verification (read-only): re-open the repository Security settings and
  compare the displayed state with the approved URL fingerprint; also inspect
  `SECURITY.md` locally:

  ```bash
  gh repo view LeonardSEO/openbola --json nameWithOwner
  rg -n "SECURITY|private disclosure" SECURITY.md
  ```

Postcondition: private reporting is enabled exactly as approved and no secret
or live customer URL is recorded in the evidence.

## 5. Release metadata and P10 artifacts

Approval needed: explicit approval for creating the release and uploading the
locally verified artifacts.

- Dry-run / preflight (read-only):

  ```bash
  git rev-parse HEAD
  git status --short
  shasum -a 256 dist/openbola-VERSION-windows-x64.zip dist/openbola-VERSION-macos-arm64.tar.gz dist/openbola-VERSION-macos-x64.tar.gz
  cat dist/SHA256SUMS
  gh release view VERSION --repo LeonardSEO/openbola
  ```

  Substitute the reviewed version and exact P10 paths locally; do not add
  unreviewed files or attach a state database, scope, log, or credential.
- STOP—obtain approval for the version, release notes, and artifact checksums:

  ```bash
  # gh release create VERSION --repo LeonardSEO/openbola --title "OpenBOLA VERSION" --notes-file RELEASE_NOTES.md dist/openbola-VERSION-windows-x64.zip dist/openbola-VERSION-macos-arm64.tar.gz dist/openbola-VERSION-macos-x64.tar.gz dist/SHA256SUMS
  ```

- Post-action verification (read-only):

  ```bash
  gh release view VERSION --repo LeonardSEO/openbola --json tagName,name,isDraft,isPrerelease,assets
  gh release download VERSION --repo LeonardSEO/openbola --pattern SHA256SUMS --dir /tmp/openbola-release-check
  ```

Postcondition: the immutable tag/commit SHA, release metadata, and uploaded
checksums match the reviewed local evidence. If any digest or asset differs,
abort; do not delete and recreate a release.

## 6. Social-preview upload

Approval needed: explicit approval for uploading the checked-in preview.

- Dry-run / preflight (read-only):

  ```bash
  uv run python scripts/check_launch_assets.py docs/assets/openbola-social-preview.svg --kind social
  git status --short docs/assets/openbola-social-preview.svg
  ```

- STOP—obtain approval, then upload `docs/assets/openbola-social-preview.png`
  (or the reviewed SVG-derived image) through the repository Settings UI. Do
  not upload a private screenshot, customer data, or an unreviewed derivative.
- Post-action verification (read-only): reopen the repository Overview and Settings pages
  and record the displayed preview's immutable repository URL plus the source
  asset SHA-256. No token or session URL belongs in the evidence.

Postcondition: the displayed preview is the reviewed local composition and no
remote asset or tracking resource was introduced.

## Evidence and closeout

Record only:

- approved operation and approver/time;
- immutable repository URL, commit SHA, tag/release URL, and artifact SHA-256
  values;
- read-only command results and bounded GitHub settings screenshots/URLs;
- abort reason and preserved local/remote state for any failed postcondition.

The roadmap marker is **P11 local launch materials complete; external GitHub launch pending approval** until every approved mutation has its own postcondition and
evidence. Native Windows x64 and macOS x64/arm64 clean-machine acceptance is
also unverified until P10 artifacts run on their respective machines or CI.
