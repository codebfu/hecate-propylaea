# CI versioning

Master builds auto-increment the semver **patch** segment using git tags `vX.Y.Z` as the source of truth.

## How it works

1. `ci/resolve-version.sh` reads `MAJOR.MINOR` from `Cargo.toml` (bump those manually when needed).
2. On **master**, every CI pipeline creates and pushes a new `vX.Y.Z` with the next patch number (even if the commit already has older semver tags).
3. That covers re-runs and downstream triggers (for example core → platform installers) so rebuilt artifacts never reuse a package version when dependencies changed.
4. Tag pipelines (`CI_COMMIT_TAG`) and branch builds on non-`master` branches use the resolved tag or the static `Cargo.toml` version without creating tags.

Docker images are tagged with the resolved version (for example `propylaea-0.1.0`).

## GitLab project settings (required)

Configure these once per GitLab project:

| Setting | Value |
|---------|-------|
| **CI/CD → Token Access → Allow CI job token to push to repository** | Enabled (`write_repository`) |
| **CI/CD → Token Access → CI job token allowlist** | Allow `hecate/hecate` so `ci/clone-hecate.sh` can fetch protocol |

Without `write_repository`, the `resolve_version` job cannot push tags and master builds will fail when creating a new version.


## Scripts

| Script | Purpose |
|--------|---------|
| `ci/resolve-version.sh` | Resolve or create `vX.Y.Z`, write `version.env` |
| `ci/require-version-tag-on-commit.sh` | Fail when the current commit has no semver tag (gates registry push) |
| `ci/apply-version.sh` | Patch `Cargo.toml` (and npm `package.json` in hecate) before build |

## Registry push gate

The `push` job runs only after `check_version_tag` succeeds. That job verifies a `vX.Y.Z` tag points at the current commit (created by `resolve_version` on master, or supplied by a tag pipeline). If tagging failed, registry push is skipped.

## Local use

```bash
bash ci/resolve-version.sh
source version.env
echo "$VERSION"
```

Local runs compute the next version but do not push git tags.
