# Making a rustls release

This is a checklist for steps to make before/after making a rustls release.

1. Attend to the README.md: this appears on crates.io for the release, and can't be edited after
   the fact.
   - Ensure the version has a good set of release notes.  Move old release notes to OLDCHANGES.md
     if this is getting excessively long.
   - Write the version and date of the release.
2. Run `cargo update` followed by `cargo outdated`, to check if we have any
   dependency updates which are not already automatically taken by their semver specs.
   - If we do, take them if possible with separate commits (but there should've been
     dependabot PRs submitted for these already.)
3. Now run `cargo test --all-features` to ensure our tests continue to pass with the
   updated dependencies.
4. Update `rustls/Cargo.toml` to set the correct version.
5. Make a commit with the above changes, something like 'Prepare $VERSION'.  This
   should not contain functional changes: just versions numbers, and markdown changes.
6. Do a dry run: in `rustls/` check `cargo publish --dry-run`
7. Push the above commit.  Wait for CI to confirm it as green.
   - Any red _should_ naturally block the release.
   - If rustc nightly is broken, this _may_ be acceptable if the reason is understood
     and does not point to a defect in rustls.  eg, at the time of writing in releasing 0.20:
     - `cargo fuzz` is broken: https://github.com/rust-fuzz/cargo-fuzz/issues/276
     - oss fuzz is broken: https://github.com/google/oss-fuzz/issues/6268
     (Both of these share the same root cause of LLVM13 breaking changes; which are
      unfortunately common when rustc nightly takes a new LLVM.)
8. Tag the released version: `git tag -m '0.20.0' v/0.20.0`
9. Push the tag: `git push --tags`
10. Do the release: `cargo publish` when sat in `rustls/`.

## Post-release things

- Update dependent crates (eg, hyper-rustls, rustls-native-certs, etc.)


