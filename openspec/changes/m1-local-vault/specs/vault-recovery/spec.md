# Spec Delta

## Purpose

Lets a user regain access to their vault after losing the passphrase or the device, without weakening normal unlock.

## ADDED Requirements

### Requirement: Recovery phrase at creation
Vault creation SHALL generate a 24-word BIP-39 phrase from 256 bits of entropy, show it once, and require the user to re-enter three randomly chosen words before the vault is usable.

#### Scenario: Confirmation required
- **WHEN** the user enters a wrong confirmation word during init
- **THEN** init does not complete and the user is asked again

### Requirement: Restore from phrase
`smith vault recover` SHALL unlock the vault with the recovery phrase and require a new passphrase, rewriting only the passphrase wrap.

#### Scenario: Lost passphrase
- **WHEN** the user runs recover with the correct phrase and sets a new passphrase
- **THEN** all secrets decrypt with the new passphrase

#### Scenario: Wrong phrase
- **WHEN** the phrase has a bad checksum or does not unwrap the vault key
- **THEN** recovery fails without modifying the vault

### Requirement: Rotate recovery phrase
`smith vault recovery rotate` SHALL replace the recovery wrap with one from a newly generated phrase, after unlocking with the passphrase.

#### Scenario: Old phrase invalid
- **WHEN** the recovery phrase is rotated
- **THEN** the previous phrase no longer unlocks the vault
