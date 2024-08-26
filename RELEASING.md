## Before making a release

1. Run `cargo update` followed by `cargo outdated`, to check if we have any
   dependency updates which are not already automatically taken by their semver specs.
   - If we do, take them if possible.  There should be dependabot PRs submitted for these already, but if
     not make separate commits for these and land those first.
2. Run the daily-tests CI workflow to check if we have any unfixed regressions.
   You can run the workflow manually for the to-be-released branch by visiting
   [the daily-tests workflow](https://github.com/rustls/rustls/actions/workflows/daily-tests.yml)
   in your browser and selecting "Run workflow".
3. Update `rustls/Cargo.toml` to set the correct version.
4. Make a commit with the new version number, something like 'Prepare $VERSION'.  This
   should not contain functional changes: just version numbers, and perhaps markdown changes.
5. Do a dry run: in `rustls/` check `cargo publish --dry-run`.
   - Do not use `--allow-dirty`; use a separate working tree if needed.
6. Come up with text detailing headline changes for this release.  General guidelines:
   * :green_heart: include any breaking changes.
   * :green_heart: include any major new headline features.
   * :green_heart: include any major, user-visible bug fixes.
   * :green_heart: include any new API deprecations.
   * :green_heart: emphasise contributions from outside the maintainer team.
   * :x: omit any internal build, process or test improvements.
   * :x: omit any minor or user-invisible bug fixes.
   * :x: omit any changes to dependency versions (unless these cause breaking changes).
7. Open a PR with the above commit and include the release notes in the description.
   Wait for review and CI to confirm it as green.
   - Any red _should_ naturally block the release.
   - If rustc nightly is broken, this _may_ be acceptable if the reason is understood
     and does not point to a defect in rustls.  eg, at the time of writing in releasing 0.20:
     - `cargo fuzz` is broken: https://github.com/rust-fuzz/cargo-fuzz/issues/276
     - oss fuzz is broken: https://github.com/google/oss-fuzz/issues/6268
     (Both of these share the same root cause of LLVM13 breaking changes; which are
      unfortunately common when rustc nightly takes a new LLVM.)

## Making a release

1. Tag the released version: eg. `git tag -m '0.20.0' v/0.20.0`
2. Push the tag: eg. `git push origin v/0.20.0`
3. Do the release: `cargo publish` when sat in `rustls/`.
   - Do not use `--allow-dirty`; use a separate working tree if needed.

## After making a release

1. Create a new GitHub release for that tag.  Use "Generate release notes" (against the tag for the previous release)
   as a starting point for the release description.  Then add the "headlines" produced earlier at the top.
2. Update dependent crates (eg, hyper-rustls, rustls-native-certs, etc.) if this was a semver-incompatible release.

## Maintenance point releases

When point releases for bug fixes and small backwards compatible changes, but `main` contains unreleased breaking
changes we follow a modified release process using a longer-lived maintenance branch.

1. Check if there is an existing release branch, e.g. `rel-0.21` for point releases in the `0.21.x` series.
   - If there is, use that branch.
   - If there is not, create a new branch from the tag for the previous release, e.g. `git checkout -b rel-0.21 v/0.21.0`.
     Remember to also create a branch protection rule for the release branch, matching the settings from `main`.
2. Make pull-requests for any changes you want to include in the point release, targeted against the release branch.
3. Follow the usual release process, but use the release branch instead of `main` when making the release.
   - For example, `cargo publish` should be run from the release branch, not `main`.
