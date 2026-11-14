# Spec Delta

## Purpose

Determines which paid features a device may use, verifiably and offline, without ever restricting access to the user's own secrets.

## ADDED Requirements

### Requirement: Offline license verification
Locksmith SHALL determine the tier from a signed license verified locally against embedded public keys, with no network access required at verification time.

#### Scenario: Offline Pro
- **WHEN** a device with a valid Pro lease is offline
- **THEN** Pro features work

### Requirement: Device activation and refresh
`smith license activate` SHALL bind the device to the account via a browser sign-in and obtain a lease valid for 30 days, refreshed automatically before expiry, with 14 days of grace after expiry.

#### Scenario: Grace period
- **WHEN** the lease expired 10 days ago and refresh has failed
- **THEN** Pro features still work and doctor warns about the refresh failure

#### Scenario: Device limit
- **WHEN** a Pro account with 5 active devices activates a sixth
- **THEN** activation fails with a message listing devices and how to remove one

### Requirement: Never hold secrets hostage
When a license is expired past grace, revoked, missing or invalid, Locksmith SHALL operate at Free tier, SHALL keep unlock, export and all Free features working, and SHALL keep paid configuration intact but inactive.

#### Scenario: Cancelled subscription
- **WHEN** a Pro user's subscription ends and grace passes
- **THEN** DB relays do not start, existing DB relay configuration is preserved, and `smith export` and `smith run` work

### Requirement: Limits apply to creation only
Tier limits SHALL be enforced when creating projects, upstreams or devices, and SHALL NOT disable use of items that already exist.

#### Scenario: Downgraded with 5 projects
- **WHEN** a downgraded user with 5 projects uses project 4
- **THEN** it works, and creating a sixth project is refused with an upgrade message

### Requirement: Trial
`smith license trial` SHALL grant 14 days of Pro once per account.

#### Scenario: Second trial
- **WHEN** an account that already had a trial requests another
- **THEN** the request is refused
