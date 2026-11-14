# Spec Delta

## Purpose

Lets customers buy, change and cancel Locksmith subscriptions and keeps their entitlements in step with payment state.

## ADDED Requirements

### Requirement: Self-serve purchase
Users SHALL be able to purchase Pro or Team, monthly or annually, via hosted checkout started from the CLI, desktop app or website, and receive entitlements within 60 seconds of payment.

#### Scenario: Upgrade from CLI
- **WHEN** the user runs `smith upgrade pro` and completes checkout
- **THEN** within 60 seconds `smith license status` shows Pro

### Requirement: Subscription lifecycle sync
Subscription changes (upgrade, downgrade, seat change, cancellation, renewal) SHALL be reflected in licenses idempotently, and a reconciliation job SHALL correct any drift daily.

#### Scenario: Duplicate webhook
- **WHEN** the same subscription-updated event is delivered twice
- **THEN** the account state changes once

### Requirement: Dunning
After a failed payment the account SHALL keep full features for 7 days while payment is retried, then downgrade to Free under the never-hostage rule.

#### Scenario: Payment fails
- **WHEN** a renewal payment fails and is not recovered within 7 days
- **THEN** the account becomes Free and the user is emailed before and at downgrade

### Requirement: Team seats
Team admins SHALL be able to add and remove seats and assign them to members, with prorated billing.

#### Scenario: Add seat
- **WHEN** an admin adds a seat and assigns it to an invited member
- **THEN** the member's devices activate at Team tier
