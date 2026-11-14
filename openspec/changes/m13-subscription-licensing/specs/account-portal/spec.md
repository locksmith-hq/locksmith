# Spec Delta

## Purpose

Gives customers a web place to manage their account, plan, devices, seats and invoices without contacting support.

## ADDED Requirements

### Requirement: Account self-service
Signed-in users SHALL be able to view their plan, open the billing portal, list and remove devices, and download an offline license file when their plan allows it.

#### Scenario: Remove lost laptop
- **WHEN** the user removes a device in the portal
- **THEN** that device's lease is not refreshed and the device slot is freed immediately

### Requirement: Passwordless sign-in
The portal SHALL support email magic links and GitHub sign-in, and SHALL NOT store passwords.

#### Scenario: Magic link
- **WHEN** the user requests a magic link
- **THEN** a single-use link valid for 15 minutes is emailed
