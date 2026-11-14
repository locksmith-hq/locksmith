# Spec Delta

## ADDED Requirements

### Requirement: Compromise-resilient update verification
Clients SHALL install only targets authenticated by a threshold-signed, non-expired update metadata chain, and SHALL reject rollback to older metadata versions, expired metadata, and targets whose hash or length mismatch.

#### Scenario: Rollback attack
- **WHEN** a mirror serves older, validly signed metadata
- **THEN** the client rejects it and keeps the current version

#### Scenario: Freeze attack
- **WHEN** the timestamp metadata has expired
- **THEN** the client reports the update channel as stale in `smith doctor` and installs nothing

### Requirement: Platform signature verification
Before installation the client SHALL verify the platform code signature of the new binaries in addition to update metadata.

#### Scenario: Unsigned binary
- **WHEN** a target passes metadata checks but its macOS code signature is invalid
- **THEN** installation is aborted and reported

### Requirement: Channels
Users SHALL be able to select `stable`, `beta` or `nightly`, and enterprise policy SHALL be able to pin a version.

#### Scenario: Switch to beta
- **WHEN** the user runs `smith update channel beta`
- **THEN** subsequent checks consider beta targets

### Requirement: Staged rollout
A target with a rollout percentage SHALL be installed only by clients whose locally computed bucket falls below that percentage.

#### Scenario: Ten percent
- **WHEN** a version is at 10% rollout
- **THEN** a client whose bucket is 42 does not install it, and a client whose bucket is 7 does

### Requirement: Kill switch
Removing a version from channel metadata SHALL stop further installations of it within one timestamp period.

#### Scenario: Yanked release
- **WHEN** version 1.4.0 is yanked
- **THEN** clients that have not installed it do not install it after their next check

### Requirement: Safe daemon update
Updating SHALL drain the daemon, swap binaries atomically, restart the service, and roll back automatically if the post-update health check fails within 60 seconds.

#### Scenario: Failing health check
- **WHEN** the new daemon fails its health check
- **THEN** the previous version is restored and running, and the failure is reported to the user

### Requirement: Package manager deference
When Locksmith was installed by a package manager, the updater SHALL only notify about updates and SHALL NOT modify package-managed files.

#### Scenario: Homebrew install
- **WHEN** an update is available for a Homebrew install
- **THEN** the user is told to run `brew upgrade locksmith` and no files are changed

### Requirement: Security floor without hostage
Versions below the published minimum secure version SHALL show a blocking warning when starting new sessions, overridable for 24 hours, and SHALL never block unlock or export.

#### Scenario: Vulnerable version
- **WHEN** the installed version is below the minimum secure version
- **THEN** `smith session start` warns and requires `--accept-risk`, while `smith export` works normally
