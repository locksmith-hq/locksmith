# gateway-aws-sts Specification

## Purpose

TBD - created by archiving change d2-aws-sts. Update Purpose after archive.

## Requirements

### Requirement: Gateway issues short-lived scoped AWS credentials
The gateway SHALL expose `POST /v1/aws/credentials`, which authenticates the agent token, checks an unexpired `delegate` grant for an AWS binding with `vend = true`, calls STS `AssumeRole` for the bound role with an inline session policy rendered from the grant, and returns `AccessKeyId`, `SecretAccessKey`, `SessionToken` and `Expiration`. The base credential and role trust SHALL never be returned.

#### Scenario: Agent uses the AWS CLI against Floci
- **WHEN** an agent with a grant runs `aws sts get-caller-identity` through a profile whose `credential_process` is `smith aws credential-process`, with STS pointed at Floci
- **THEN** the call succeeds as an assumed-role session, the credentials expire within the granted duration, and the agent environment, AWS config and process arguments contain no long-lived key

#### Scenario: Duration is capped
- **WHEN** the agent requests more than the grant's maximum duration, or less than 900 seconds
- **THEN** the gateway clamps to the grant maximum or returns 400 respectively, and never exceeds 3600 seconds

### Requirement: Session policy narrows to the grant
The issued credentials SHALL carry a session policy built only from the grant's allowed actions and resources. A grant with no allow-list SHALL be refused unless the binding is explicitly marked `unrestricted`. The agent SHALL NOT be able to supply or widen the policy.

#### Scenario: Policy is rendered from the grant
- **WHEN** credentials are issued for a grant allowing `s3:GetObject` on one bucket
- **THEN** the STS request carries a session policy with exactly that action and resource, and a request body field supplying another policy is ignored

#### Scenario: Empty grant refused
- **WHEN** the grant has no actions or resources and the binding is not `unrestricted`
- **THEN** the gateway returns 403, makes no STS call and records a denied ledger event

### Requirement: Vending is off by default and bound
Credentials SHALL be issued only for a binding that sets `vend = true`, only for its role ARN and region, and only to an agent with a `delegate` grant. Every refusal SHALL occur before the base credential is decrypted.

#### Scenario: Binding without vend
- **WHEN** an agent requests credentials for a binding with `vend` unset
- **THEN** the gateway returns 403 with no decrypt call and no STS call

#### Scenario: Relay-only grant
- **WHEN** an agent holding only a `relay` grant requests credentials
- **THEN** the gateway returns 403 and records a denied ledger event

### Requirement: No base credential in output or ledger
Responses, logs, traces and ledger events SHALL contain the role ARN, region, duration and outcome only, never the base credential, the issued secret key or the session token. STS error text returned to the caller SHALL be a fixed slug.

#### Scenario: STS fails
- **WHEN** STS returns an error whose body includes request details
- **THEN** the caller sees a fixed error slug, and neither logs nor the ledger contain the base credential or response body

#### Scenario: Leak scan after issue
- **WHEN** credentials have been issued in the local smoke test
- **THEN** `just leak-scan` finds the base credential nowhere in logs, traces or ledger, and the ledger holds `aws.credentials.issued` without key material

### Requirement: Client setup is reversible and diagnosable
`smith aws setup --gateway <url>` SHALL write a profile using `credential_process` and no keys; `smith aws teardown` SHALL remove it; `smith doctor` SHALL report an `aws.vend` check that warns the credentials are agent-visible.

#### Scenario: Setup then teardown
- **WHEN** `smith aws setup` and then `smith aws teardown` run on a clean AWS config
- **THEN** the config returns to its original content and no secret was written at any point
