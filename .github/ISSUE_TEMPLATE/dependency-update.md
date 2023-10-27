---
name: Dependency Update
about: Request a dependency be updated
title: Dependency update request
labels: ''
assignees: ''

---

<!--
Please note that we are only interested in **semver-incompatible** update requests. Updates to dependencies that are 
semver-compatible can be done in dependent projects without needing changes in this repository.

For example, if you are here because you believe Rustls is bringing in dependency `foo` at version `0.2.1` and
you wish Rustls used `0.2.2` instead, you should not file an issue and instead should run `cargo update` in your
dependent project. It would only be appropriate to file an issue if you require Rustls use `foo` at version `0.3.0+`.
-->

**Checklist**
* [ ] I've searched the issue tracker for similar requests
* [ ] I've confirmed my request is for a semver-incompatible update

**Is your dependency update request related to a problem? Please describe.**
A clear and concise description of what the problem is.

**Describe the solution you'd like**
A clear and concise description of what you want to happen.

**Describe alternatives you've considered**
A clear and concise description of any alternative solutions or features you've considered.

**Additional context**
Add any other context or screenshots about the feature request here.
