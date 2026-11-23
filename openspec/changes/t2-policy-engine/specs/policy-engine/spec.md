## ADDED Requirements

### Requirement: Policy decisions come from one in-process Cedar engine
The NestJS API (`apps/api`, decision OC-9 G1) SHALL decide every authorization question through its policy module, which evaluates Cedar policies in-process (`@cedar-policy/cedar-wasm`) against one schema and returns allow or deny together with the ids of the deciding policies. The gateway SHALL act only on grants the API has already decided. A request no policy permits SHALL be denied.

#### Scenario: Default deny
- **WHEN** the policy module evaluates a request that no policy permits
- **THEN** the decision is deny and lists no permitting policy

#### Scenario: Decision names its policies
- **WHEN** a member reads secret metadata in their org
- **THEN** the decision is allow and names the built-in `member` policy

### Requirement: Built-in role policies enforce owner, admin and member
The system SHALL ship fixed Cedar policies for the T6 roles: members read metadata and use what they are granted; admins also manage projects, environments, secrets, agents and grants; owners also manage the org and its policies. Every mutating or secret-reading API route SHALL be authorized by these policies.

#### Scenario: Member cannot create a grant
- **WHEN** a `member` calls `POST /v1/agents/{id}/grants`
- **THEN** the response is `403` with problem slug `policy-denied` and no policy text

#### Scenario: Admin can create a grant
- **WHEN** an `admin` calls `POST /v1/agents/{id}/grants` for a secret in the same org
- **THEN** the grant is created and a ledger event is written

#### Scenario: Only owners change org policies
- **WHEN** an `admin` calls `POST /v1/policies`
- **THEN** the response is `403`

### Requirement: Org policies add attribute-based rules
An owner SHALL be able to add, replace and delete Cedar policies for their org. The system SHALL validate each policy against the schema before storing it, reject one that fails with the validator's message, keep every version, and write a ledger event for each change. Org policies SHALL NOT be able to override a built-in `forbid`.

#### Scenario: Invalid policy is rejected
- **WHEN** an owner posts a policy that references an unknown attribute
- **THEN** the response is `422` with the validation message and nothing is stored

#### Scenario: Environment attribute limits an agent
- **WHEN** an org policy forbids agent use in the environment named `production` and an agent with a relay grant on a `production` secret asks the gateway to relay
- **THEN** the relay is refused and the gateway audit record names the deciding policy id

#### Scenario: Policies are isolated per org
- **WHEN** org A's owner lists policies
- **THEN** no policy of org B is returned

### Requirement: Grants carry a usage mode of relay, delegate or inject
A grant SHALL have mode `relay`, `delegate` or `inject`. `relay` lets the gateway inject the value into an upstream request; `delegate` lets the gateway or `locksmithd` act with a short-lived scoped credential; `inject` lets `smith run` place the value into a process environment for a human principal. A built-in `forbid` policy SHALL deny `inject` to every `Agent` principal.

#### Scenario: Agent cannot be given inject
- **WHEN** an admin creates a grant with mode `inject` for an agent
- **THEN** the response is `403` with slug `policy-denied` and no grant is stored

#### Scenario: Relay grant does not allow delegate use
- **WHEN** an agent holding only a `relay` grant asks for delegated use of that secret
- **THEN** the gateway refuses it

#### Scenario: Existing grants keep working
- **WHEN** the migration runs on a database with S4 relay grants
- **THEN** every existing grant has mode `relay` and still relays

### Requirement: Access can be checked without acting
`POST /v1/policies/check` SHALL return the decision and deciding policy ids for a given principal, action and resource in the caller's org, without performing the action, and SHALL be available to owners and admins only.

#### Scenario: Check an agent relay
- **WHEN** an owner checks whether an agent may relay a secret it holds a relay grant for
- **THEN** the answer is allow with the deciding policy ids, and no relay or audit event of a relay occurs

### Requirement: Console and desktop show policies and modes
The web console and the desktop app SHALL show a Policies page (built-in policies read-only, org policies editable by owners with validation errors shown, and a check-access form) and a usage-mode picker on the grant form.

#### Scenario: Owner sees a validation error inline
- **WHEN** an owner saves an invalid policy in the console
- **THEN** the page shows the server's validation message and the list is unchanged

#### Scenario: Inject is not offered for agents
- **WHEN** an admin opens the grant form for an agent
- **THEN** the mode picker offers `relay` and `delegate` only
