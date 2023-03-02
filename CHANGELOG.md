# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [3.0] - 2023-03-01
### Added
- Integrated GitHub Actions workflow. Highlights:
  - Trigger workflow at a scheduled time (every Mon at 00:00).
  - The dependency review feature will scan for any vulnerabilities or invalid licenses, and the report will be available on the job logs and the job summary.
- Added CHANGELOG.md.
- Support for TPM simulator (stefanberger/swtpm).

### Changed
- The project folder structure has been changed, and all contents have been merged into a single branch (master).

### Removed
- Removed the document/tpm-appnote-ek-based-onboarding.pdf. The content of this document has been migrated to README.md.

### Security
- Fixed server dependency vulnerabilities by upgrading the versions of the following: com.h2database.h2, com.google.code.gson, org.bouncycastle.bcprov-jdk15on. A workaround has been applied to address the upgrade repercussions related to issues #3325 and #3363 for com.h2database.h2 (https://github.com/h2database).

## [x.x] - YYYY-MM-DD
- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.
