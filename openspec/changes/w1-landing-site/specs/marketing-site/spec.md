# Spec Delta

## Purpose

Presents Locksmith publicly, converts visitors into waitlist members and customers, and states security guarantees accurately.

## ADDED Requirements

### Requirement: Waitlist with consent
Visitors SHALL be able to join the waitlist with double opt-in, and SHALL be able to unsubscribe from any email.

#### Scenario: Join
- **WHEN** a visitor submits the waitlist form
- **THEN** a confirmation email is sent and they are added only after confirming

### Requirement: Pricing matches the product
The pricing page SHALL be generated from the same feature definition the product uses to enforce entitlements.

#### Scenario: Feature moved between tiers
- **WHEN** a feature's tier changes in the feature definition
- **THEN** the next site build shows it under the new tier with no manual edit

### Requirement: Honest security claims
Security pages SHALL label each protection as prevention, containment or detection, and SHALL list residual risks.

#### Scenario: Residual risk listed
- **WHEN** a visitor reads the security page
- **THEN** it lists same-user code injection and privileged host compromise as residual risks

### Requirement: No third-party tracking
The site SHALL NOT load third-party trackers or set non-essential cookies.

#### Scenario: Cookie audit
- **WHEN** an automated audit loads every page
- **THEN** no third-party script or non-essential cookie is present

### Requirement: Accessibility and performance
Every page SHALL meet WCAG 2.2 AA and score at least 95 in Lighthouse performance, accessibility, best practices and SEO.

#### Scenario: CI budget
- **WHEN** CI runs Lighthouse and axe on all pages
- **THEN** the build fails if any page is below the budget or has an axe violation
