# Locksmith v5: Master Implementation Specification

Locksmith v5 is a specialized credential broker, operation delegation engine, and execution isolation layer engineered for autonomous AI coding agents—including Anthropic Claude Code, Cursor, xAI Grok Build, OpenAI Codex, and OpenHands. It bridges the security requirements of modern password managers and secret management systems with the non-deterministic, tool-augmented execution environments of generative models. 

Locksmith ensures that persistent production credentials remain isolated from persistent storage in plaintext, are shielded from agent conversation contexts across supported interaction paths, remain protected against accidental shell history logging, and are prevented from being committed to source control systems.

---

## 1. Calibrated Threat Model and Security Boundaries

Effective security in AI agent environments demands defensible, deterministic perimeters. Rather than making ungrounded claims of universal zero-trust, Locksmith v5 defines explicit threat boundaries, rigorously distinguishing between external host threats, authorized agent sessions, untrusted subprocesses, and environmental residual risks.

### 1.1 Threat Boundary Classification Matrix

| Threat Category | Concrete Exposure Scenario | Defensive Mechanism and Enforcement Layer | Security Guarantee Level |
| :--- | :--- | :--- | :--- |
| **Agent Context Ingestion (Supported Paths)** | An agent executes commands like `printenv`, reads local manifests, or triggers verbose stack traces during debugging. | Opaque Virtual Tokens, Operation Delegation, and Multi-Encoding Aho-Corasick Stream Redactor. | Credential exposure prevention across explicitly supported and tested execution paths. |
| **Direct Helper Credential Enumeration** | An agent with arbitrary terminal access invokes `git-credential-smith get` or `aws credential_process` directly to print tokens. | Operation Delegation Brokerage, Parent-Process Lineage Checks, and One-Time IPC Capability Handoffs. | High-assurance containment; helper denies raw credential output to interactive shells. |
| **In-Session Malicious Subprocess** | An agent runs `npm install` or builds code; a malicious dependency executes as a child process within the authorized session. | Non-inheritable session handles, OS process container boundaries, per-operation capability tokens, and granular scope locks. | Defense-in-depth isolation; unverified child processes cannot inherit master session credentials. |
| **Configuration File Git Commits** | Tool convenience options record credential-bearing shell commands to local configuration files that get staged. | Deterministic PreToolUse Interception Hooks, Local `.gitignore` Inoculation, and Client-Side Pre-Commit Scanning. | Local prevention backed by recommended server-side secret scanning and push protection. |
| **Unrelated Same-User Host Process** | A separate rogue background process running under the same user UID queries local IPC channels to extract vault secrets. | Kernel-Level Peer Identity Verification (PID + Process Start Time + Binary Hash) and Noise Protocol Transport Encryption. | Operating-system-level access restriction; unauthorized local peers are rejected at handshake. |
| **Offline Storage Theft & Forensic Extraction** | An attacker gains physical possession of a powered-off workstation or an unencrypted file backup of the database. | Argon2id Key Derivation, Secure Enclave / TPM 2.0 Hardware Key Sealing, and AES-256-GCM SQLCipher Page Encryption. | Encrypted-at-rest protection against offline database theft. |
| **Residual Risk: Out-of-Band Developer Actions** | A human developer manually copies a secret from a browser and pastes it directly into the agent's chat interface. | Out of System Scope. Human-driven inputs to the model interface cannot be intercepted at the OS daemon level. | Residual Risk (Addressed via developer training and client-side chat heuristic scrubbers). |
| **Residual Risk: Privileged Host Compromise** | An attacker possesses administrative root or kernel-level code execution privileges on the host workstation. | Explicitly Out of Scope. A compromised operating system kernel supersedes all user-space isolation controls. | No Protection Possible. |

### 1.2 Distinguishing Same-User Rogue Processes from In-Session Child Processes
A critical vulnerability in legacy agent credential designs is treating all processes within an authorized session as equally trusted. Locksmith v5 formally decouples:
1. **Unrelated Same-User Processes:** Background daemons or malicious utilities running under the user's login account outside the agent's process tree. These are blocked via kernel peer attestation, binary path signature validation, and transport-level mutual authentication.
2. **In-Session Subprocesses:** Child processes deliberately or transitively spawned by the agent (e.g., build runners, dependency compilation scripts, package post-install hooks). Because these run inside the session's operating system container, Locksmith does not grant them automatic access to session credentials. Subprocesses cannot query the Locksmith daemon unless explicitly delegated an ephemeral, single-use, operation-scoped execution token.

---

## 2. Cryptographic Architecture and Multi-Wrap Envelope Encryption

Locksmith v5 implements a hierarchical envelope encryption model that decouples user authentication keys from persistent vault storage keys and individual secret encryption keys. This prevents master passphrase modifications from forcing a re-encryption of the entire database, enables independent rotation of secret records, and provides multi-modal unlock pathways.

### 2.1 The Key Derivation and Wrapping Ladder

The cryptographic ladder establishes a clear separation of concerns across key derivation, key wrapping, and authenticated data protection:

1. **Master Key Derivation (Argon2id):**
   The user-supplied passphrase ($P$) is combined with a 32-byte cryptographically secure random salt ($S$) stored in the local database header. Key derivation executes via Argon2id configured with memory-hard parameters resisting parallel GPU and ASIC hardware cracking:
   * Memory Size ($m$): 65,536 KiB (64 MiB).
   * Iterations ($t$): 3 passes.
   * Parallelism ($p$): 4 threads.
   * Output Key Length: 32 bytes (256 bits).
2. **Subkey Expansion (HKDF-SHA256):**
   The derived Master Key ($MK$) is expanded using HKDF-SHA256 with distinct domain-separated info strings to yield two independent operational subkeys:
   * **Passphrase Wrapping Key ($PWK$):** A 256-bit symmetric key derived via info string `locksmith-v5-passphrase-wrap`, dedicated exclusively to encrypting the Vault Key ($VK$).
   * **Audit MAC Key ($AMK$):** A 256-bit symmetric key derived via info string `locksmith-v5-audit-mac`, reserved for initializing the forward-secure audit ledger ratchet.
3. **The Persistent Vault Key ($VK$):**
   Upon initial vault generation, Locksmith creates a cryptographically random 256-bit symmetric Vault Key ($VK$). The Vault Key is never written to disk in plaintext. Instead, it is stored in the database header through multiple independent, parallel cryptographic wraps.
4. **Per-Secret Data Encryption Keys ($DEK$):**
   Vault items are never encrypted directly with the Vault Key. Every individual secret entry is assigned a unique, randomly generated 256-bit Data Encryption Key ($DEK$). The secret payload is encrypted with its dedicated $DEK$, and the $DEK$ is encrypted with the Vault Key ($VK$).

### 2.2 Multi-Wrap Vault Key Architecture

To provide flexible access while preserving cryptographic zero-knowledge at rest, the Vault Key ($VK$) is independently encrypted under three distinct wrapping mechanisms, each recorded in a dedicated database header record:

1. **Passphrase Wrap:** The $VK$ is encrypted using the Passphrase Wrapping Key ($PWK$) via AES-256-GCM. Unlocking requires successful Argon2id derivation from the user passphrase.
2. **Hardware Biometric Wrap:** The $VK$ is encrypted under a platform-bound key derived from the Apple Secure Enclave or Windows TPM 2.0. Unlocking delegates verification to platform biometric sensors without requiring the passphrase.
3. **Emergency Recovery Wrap:** The $VK$ is encrypted under an independent Recovery Wrapping Key ($RWK$) derived from a 24-word BIP-39 mnemonic seed phrase.

Updating a user master password requires only re-deriving $PWK$ via Argon2id and re-encrypting the 32-byte Vault Key ($VK$) in the passphrase wrap record. The hardware wrap, recovery wrap, and all individual secret DEKs remain untouched, guaranteeing sub-second password rotations without bulk database rewriting.

### 2.3 Strict Authenticated Associated Data (AAD) Binding

To prevent ciphertext substitution, relocation across environments, or cross-record splicing attacks, both encryption tiers enforce strict Authenticated Associated Data ($AAD$) binding using AES-256-GCM:

* **Tier 1 (DEK Encryption Layer):**
  The 32-byte $DEK$ is encrypted under the Vault Key ($VK$). The AEAD associated data ($AAD_{DEK}$) is constructed as a canonical, length-prefixed binary concatenation of:
  * Schema Version Identifier (e.g., `v5.0`).
  * Field Purpose Marker (e.g., `vault-dek-wrap`).
  * Target Secret UUID.
  * Project UUID.
  * Environment Identifier.
  * Vault Key Version Counter.
* **Tier 2 (Payload Encryption Layer):**
  The plaintext secret payload is encrypted under the Data Encryption Key ($DEK$). The AEAD associated data ($AAD_{Payload}$) is constructed as a canonical binary concatenation of:
  * Schema Version Identifier (e.g., `v5.0`).
  * Field Purpose Marker (e.g., `secret-payload-data`).
  * Target Secret UUID.
  * Canonical Key Name (e.g., `STRIPE_SECRET_KEY`).
  * Secret Version Integer.
  * Upstream Origin Type Identifier.

If an attacker manipulates the database file to copy an encrypted payload from a `development` record into a `production` record, the authentication tag validation fails immediately during decryption due to $AAD$ mismatch, preventing ciphertext transplant attacks.

### 2.4 Cryptographic Nonce Management and Limits

Locksmith v5 enforces strict initialization vector uniqueness across all AES-256-GCM operations:
* **Nonce Structure:** All AES-256-GCM nonces are exactly 96 bits (12 bytes) in length, generated using a cryptographically secure pseudorandom number generator (CSPRNG).
* **Invocation Lifetime Limits:** Because AES-GCM experiences catastrophic key recovery vulnerabilities under nonce reuse, any single Data Encryption Key ($DEK$) is restricted to encrypting a maximum of $2^{16}$ payload revisions. Upon approaching this threshold, Locksmith forces a mandatory DEK rotation.
* **Vault Key Nonce Partitioning:** The Vault Key encrypts individual DEKs using random 96-bit nonces. Because the total number of vault secrets on a workstation is orders of magnitude below the birthday bound for 96-bit nonces ($2^{32}$ operations for a $2^{-32}$ collision probability), random nonce generation remains provably secure.

---

## 3. Hardware-Backed Biometric Security & Enrollment Semantics

Locksmith v5 integrates directly with native hardware security coprocessors on macOS and Windows to provide biometric authentication without compromising zero-knowledge guarantees.

### 3.1 macOS Secure Enclave Architecture & ECDH Key Agreement

The Apple Secure Enclave Processor (SEP) is an isolated hardware subsystem featuring dedicated memory and hardware cryptographic accelerators. Because the SEP does not support direct symmetric AES wrapping of arbitrary user-provided data blobs, Locksmith implements an authenticated Elliptic Curve Diffie-Hellman (ECDH) key agreement protocol:

1. **Hardware Key Pair Provisioning:**
   During vault initialization, Locksmith requests Keychain Services to generate an asymmetric NIST P-256 elliptic curve key pair inside the Secure Enclave (`kSecAttrKeyTypeECSECPrimeRandom` bound to `kSecAttrTokenIDSecureEnclave`).
2. **Biometric Access Control Flags:**
   The hardware private key is constrained via `SecAccessControlCreateWithFlags` using explicit platform flags:
   * **`kSecAccessControlBiometryCurrentSet`:** Enforces strict hardware binding. If the user enrolls a new fingerprint or reconfigures Touch ID/Face ID, the hardware key is automatically and permanently invalidated by the Secure Enclave. This prevents an attacker who learns a device passcode from adding their own biometric and accessing the vault.
   * **`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:** Prevents migration via iCloud Keychain or unencrypted iTunes/Finder disk backups.
3. **ECDH Key Agreement Wrapping Protocol:**
   To create the hardware biometric wrap for the Vault Key ($VK$):
   * Locksmith exports the public key of the Secure Enclave P-256 key pair.
   * Locksmith generates a fresh, ephemeral software-based NIST P-256 key pair.
   * Locksmith performs an ECDH key agreement between the ephemeral private key and the Secure Enclave public key, deriving a 256-bit shared point.
   * The shared point is expanded via HKDF-SHA256 (with info string `locksmith-v5-sep-wrap`) to produce a symmetric Hardware Wrapping Key ($HWK$).
   * Locksmith encrypts the Vault Key ($VK$) using $HWK$ via AES-256-GCM.
   * The ephemeral public key, the 12-byte nonce, the 16-byte authentication tag, and the ciphertext are stored in the database's hardware wrap record. The ephemeral private key is immediately zeroized.
4. **Biometric Unlock Protocol:**
   To unlock via Touch ID:
   * Locksmith reads the ephemeral public key from the database header.
   * Locksmith requests Keychain Services to execute an ECDH agreement between the hardware-resident SEP private key and the stored ephemeral public key.
   * macOS halts execution and prompts the user for Touch ID verification.
   * Upon successful biometric verification within isolated hardware, the Secure Enclave computes the shared point and outputs it to the daemon process.
   * Locksmith runs the identical HKDF-SHA256 expansion to reconstruct $HWK$, decrypts the Vault Key ($VK$), and loads it into locked process memory.
5. **Enrollment Invalidation Fallback:**
   If biometric enrollment changes, the Secure Enclave invalidates the private key, returning an authorization error (`errSecAuthFailed`). Locksmith catches this error, notifies the user that biometric credentials have changed, and falls back gracefully to Master Passphrase entry. Upon successful passphrase entry, Locksmith provisions a new SEP key pair and updates the hardware wrap record.

### 3.2 Windows Hello and TPM 2.0 Integration

On Windows workstations, Locksmith utilizes the Trusted Platform Module (TPM 2.0) through Cryptography Next Generation (CNG) APIs:

* **TPM Key Storage Provider:** The daemon provisions an asymmetric RSA-2048 or ECC NIST P-256 key pair directly inside the TPM hardware boundary using the Microsoft Platform Crypto Provider (`MS_PLATFORM_CRYPTO_PROVIDER`) or Key Storage Provider (`MS_NGC_KSP`).
* **UI Policy Specification:** Key creation attaches an explicit `NCRYPT_UI_POLICY` flag enforcing Windows Hello biometric verification (Fingerprint, Facial Recognition, or PIN).
* **Hardware Asymmetric Wrapping:** The Vault Key ($VK$) is encrypted using the TPM public key. During unlock, Locksmith calls `NCryptDecrypt`, prompting the Windows Hello verification broker and executing cryptographic unwrapping entirely within the physical TPM boundary.


## 4. Practical Memory Hygiene and Buffer Lifetime Management

Attempting to enforce universal guard pages and non-swappable allocations around every single allocated byte in an application creates severe performance bottlenecks and triggers operating system resource failures. Locksmith v5 implements a pragmatic, defense-in-depth memory hygiene architecture focusing strictly on cryptographic secrets and derived key material.

### 4.1 Memory Protection Primitives

* **Standardized Secret Containers:** Locksmith standardizes on audited system abstractions, specifically the secrecy and zeroize ecosystems in Rust. Sensitive types are wrapped in specialized containers that disable cloning, prevent implicit string formatting (blocking accidental log leaks), and prohibit serialization.
* **Deterministic Compiler-Enforced Zeroization:** All buffers holding derived master keys, wrapping keys, per-secret DEKs, or plaintext credentials implement ZeroizeOnDrop. Upon falling out of scope, the memory buffers are wiped using optimizer-barrier assembly routines (explicit_bzero on Unix, SecureZeroMemory on Windows), preventing the Rust compiler from optimizing away the cleanup.
* **Best-Effort Memory Pinning (mlock / VirtualLock):** Operating systems enforce hard process limits on locked memory. Locksmith attempts to lock the memory pages containing the active Vault Key and transient DEK buffers using POSIX mlock or Windows VirtualLock. If resource limits prevent page locking, Locksmith emits a security audit warning, falls back to standard protected heap allocations, and continues execution, ensuring system stability rather than unrecoverable process crashes.
* **Core Dump Invalidation:** During daemon startup, Locksmith explicitly disables operating system crash and core dumps via system controls (setting core limits to zero), ensuring that sudden termination or kernel crashes cannot write decrypted memory pages to persistent disk images.
* **Volatile Lifetime Minimization:** Plaintext credentials are decrypted strictly on-demand and retained in process memory only for the millisecond duration necessary to establish a network socket, perform cryptographic HMAC signing, or stream to a child PTY. Decrypted secrets are never retained in global daemon caches across idle session intervals.


## 5. Capability-Based Authorization and Subprocess Isolation

A foundational vulnerability identified in prior architectures was session capability inheritance: when an authorized AI agent executes an untrusted build tool or dependency script, the child process inherits the session's environment variables and container group. In naive capability models, this child process could present the inherited session token to the vault daemon and dump credentials. Locksmith v5 resolves this through multi-attribute process binding, non-inheritable capability handoffs, and process boundary containment.

### 5.1 Multi-Attribute Process Lineage Verification

Locksmith does not rely on process identifiers (PIDs) alone, as operating systems rapidly recycle PIDs. Every IPC request reaching the Locksmith daemon undergoes rigorous multi-attribute kernel verification:

* **PID and Monotonic Process Start Time:** On macOS (via sysctl and proc_pidinfo) and Linux (via procfs), Locksmith queries the kernel for the process creation timestamp. The session lease binds to the exact (PID, Start_Time) tuple, rendering PID reuse attacks impossible.
* **Binary Path and Cryptographic Code Signature:** On macOS, the daemon calls SecCodeCheckValidity against the connecting peer to ensure its binary signature matches authorized developer tool certificates. On Linux, the daemon inspects process execution links to verify the executable binary path.
* **Container Group Membership:** The daemon confirms that the connecting process resides within the designated operating system container boundary (a macOS Mach audit session, a Linux cgroup v2 controller, or a Windows Job Object).

### 5.2 Non-Inheritable Capability Architecture

To isolate untrusted child processes executed by an agent:

1. **Non-Inheritable File Descriptor IPC:** Where supported, the CLI passes communication capability to child processes via inherited anonymous Unix Domain Socket file descriptors rather than ambient environment variables.
2. **Environment Variable Exclusion for Sub-Commands:** When the agent executes commands flagged as dependency installers or build routines, the Locksmith execution shim automatically purges LOCKSMITH_SESSION_TOKEN from the child process's spawned environment.
3. **Operation-Scoped Ephemeral Tokens:** For workflows requiring credential access, the daemon never issues broad read tokens. Instead, it issues single-use, cryptographically signed capability tokens bound to a single operation. If a child process captures this token, it cannot reuse it to query other project credentials.

### 5.3 Operating System Container Primitives

Locksmith coordinates with native OS isolation mechanisms to enforce hard process boundaries around agent execution trees:

* **Windows Job Objects:** The CLI creates an anonymous Windows Job Object configured with termination on job close limits. All processes launched by the agent are assigned to this Job Object. If the agent session terminates or is revoked, the operating system kernel instantly terminates the entire process tree, preventing orphaned background worker processes from continuing execution.
* **Linux cgroups v2 & Namespaces:** The CLI launches the agent within an isolated cgroup v2 slice and a transient mount namespace. Egress network access can be clamped, and file system access is constrained away from sensitive host directories.
* **macOS Mach Audit Sessions:** The CLI spawns the agent inside a dedicated Mach security audit session, enabling discrete auditing and process tracking via native kernel audit pipes.


## 6. Operation Delegation and Multi-Modal Protocol Virtualization

Relying on credential helpers or proxy shims to hand raw temporary credentials to an agent creates an unavoidable disclosure risk: an autonomous agent with terminal execution rights can invoke credential helpers directly or inspect tool configuration outputs to print cleartext tokens into its context window.

Locksmith v5 shifts the primary security architecture from Credential Handover to Operation Delegation: whenever possible, the agent requests Locksmith to perform or tunnel the authenticated operation, rather than receiving the underlying credential.

### 6.1 Mode A: Delegated Operation Interfaces (Primary Architectural Path)

Locksmith provides dedicated, protocol-specific adapters that execute operations on behalf of the agent or tunnel traffic without exposing credentials:

#### 1. Delegated Git Operations (git-credential-smith)
* **The Vulnerability in Standard Helpers:** Standard Git credential helpers output username and password on stdout when invoked with the get action. An agent running the helper directly in the shell captures the token.
* **Locksmith Delegated Enforcement:** Locksmith's credential helper verifies that its immediate parent process is the native Git binary (by inspecting kernel process tables and parent start times). If an agent attempts to invoke the helper directly from an interactive shell, the helper denies the request and records an audit security violation.
* **Dynamic Ephemeral Tokens:** When invoked legitimately by Git, Locksmith emits a cryptographic single-use token valid for exactly 60 seconds, bound exclusively to the target Git remote URL and the specific repository push or pull operation.

#### 2. Delegated Cloud Operations (AWS & Cloud CLI Brokers)
* **The Vulnerability in Credential Process Helpers:** A standard AWS credential process prints a JSON payload containing access keys and session tokens to standard output. An agent can invoke the process directly to capture the temporary session keys.
* **Locksmith STS Delegation & Scoped Role Assumption:** Locksmith integrates with AWS Security Token Service (STS) to generate down-scoped, short-lived session tokens (15-minute expiration). The session tokens are bound to an explicit inline session policy that restricts access strictly to declared project resources. Even if an agent captures the temporary token from memory, the credential cannot be used for privilege escalation or lateral cloud movement.

#### 3. Database Relay Tunnels (Zero-Password Database Access)
* **The Vulnerability:** Passing database connection strings with embedded passwords in environment variables exposes credentials via command arguments, application configuration files, and crash dumps.
* **Locksmith Local Socket Relay:** Locksmith provisions a local loopback TCP port or Unix Domain Socket tunnel for database connections. The agent configures its application to connect to the local loopback port with an empty password. Locksmith terminates the local connection, injects the real database password or mutual TLS client certificate, establishes the secure upstream connection, and proxies wire data bidirectionally. The agent executes migrations and queries without ever possessing the database password.

### 6.2 Mode B: Loopback Egress Proxy (Opt-In REST/API Path)

For general HTTP/HTTPS interactions with third-party SaaS APIs, Locksmith provides a scoped loopback egress proxy.

#### The Technical Architecture: TLS Interception vs. Transparent Forwarding
Transparent HTTP CONNECT proxies cannot inspect or modify encrypted HTTPS request headers or JSON bodies without terminating TLS. Locksmith v5 resolves this by explicitly defining two proxy operational modes:

1. **Transparent Host Forwarding (No TLS Termination - Preferred):**
   * The agent sends requests over plain HTTP to a dedicated local loopback endpoint.
   * Locksmith's loopback service intercepts the plain HTTP request, validates the synthetic opaque token, replaces it with the live secret in memory, establishes an outbound, fully authenticated HTTPS connection with the target host, and returns the response to the agent.
   * This mode requires zero certificate installation, eliminates TLS termination risks, and does not break under certificate pinning.
2. **Explicit Local CA TLS Termination (Opt-In Full Proxy):**
   * For toolchains requiring standard HTTPS proxying, Locksmith generates a unique, local Root Certificate Authority (CA) during installation.
   * The local CA certificate is registered in the developer workstation's operating system trust store (macOS System Keychain / Windows Certificate Store).
   * **Documented Limitations:** The documentation explicitly highlights that tools utilizing pinned certificates, custom CA bundles, or mutual TLS will reject the proxy connection, and directs developers to Mode A or Mode B (Host Forwarding) for those workloads.

#### Synthetic Opaque Token Format and Replacement
* **Token Structure:** Synthetic tokens are formatted as high-entropy identifiers mimicking provider key formats (e.g., `lsk_live_stripe_9f83b2`).
* **Out-of-Band Substitution:** When an outbound request is dispatched through the proxy, the proxy parses request headers, swaps the synthetic token with the live secret in socket buffers, and dispatches the call.
* **Egress Response Cleansing:** Response bodies and response headers are parsed in streaming chunks; any reflection of the live secret is masked before returning the payload to the agent process.

### 6.3 Mode C: In-Process PTY Execution Shims

For legacy scripts that strictly require environment variable injection:
* The CLI executes sub-processes using allocated pseudo-terminals (PTYs) via portable-pty.
* Credentials are injected directly into volatile process memory tables of the child process at launch, bypassing disk writes.
* The PTY output is continuously piped through the streaming redactor to catch any credential echoes before terminal display.


## 7. Output Redaction and Layered Repository Protection

Accidental credential exposure occurs most frequently when agents dump terminal outputs, read configuration files, or commit local files to version control. Locksmith provides deterministic barriers at the execution layer.

### 7.1 Multi-Encoding Aho-Corasick Stream Redactor

Commands executed through Locksmith pass their standard output and standard error streams through a streaming string matching automaton:

* **Pattern Compilation:** For every active secret authorized within a session, Locksmith compiles a multi-representation dictionary into an Aho-Corasick automaton:
  1. *Plaintext UTF-8 string.*
  2. *Base64-encoded representations,* including all three possible 24-bit byte-alignment offsets and URL-safe Base64 variants.
  3. *Hexadecimal representations* in both lowercase and uppercase notation.
  4. *URL/Percent-encoded representations.*
  5. *JSON-escaped string representations* (handling escaped quotes and forward slashes).
* **Streaming Correctness & Chunk Boundary Handling:**
  * **Bounded Carry-Over Buffers:** When streaming output chunks arrive from a PTY or socket, a secret string might be split across two consecutive chunks. Locksmith maintains a small sliding carry-over buffer equal to the maximum secret length minus one byte, ensuring patterns split across chunk boundaries are matched.
  * **UTF-8 Boundary Alignment:** The redactor ensures that byte boundaries do not split multi-byte UTF-8 code points, preventing corrupted terminal output.
  * **Backpressure Management:** Redaction processing operates asynchronously with bounded channel buffers to prevent memory bloat during massive terminal log bursts.
* **Masking:** Any matching sequence is replaced with an opaque redaction identifier (e.g., `[REDACTED_BY_LOCKSMITH:<UUID>]`) before the stream reaches the terminal or the agent's context history.

### 7.2 Deterministic Tool Shims & Layered Repository Protection

Relying solely on system prompts in `SKILL.md` is inherently probabilistic; agents often bypass instructions when handling complex debugging tasks. Locksmith deploys native binary shims and repository inoculation:

* **File Inspection Guards:** Intercepts agent commands attempting to execute `cat .env`, `head .env`, `source .env`, `printenv`, or `export $(cat .env)`. The shim blocks execution, returns an exit code of zero, and emits virtualized mock descriptors, preventing raw environment dumps from entering conversation transcripts.
* **Git Allowlist Protections:** When an agent runs `git add .` or attempts to stage local configuration files (such as `.claude/settings.local.json`), the shim intercepts the operation and removes sensitive configuration files from the Git staging index, preventing the committal of local allowlist files.
* **Layered Defense-in-Depth:**
  * *Local Inoculation:* `smith init` installs a pre-commit hook that scans staged files with Aho-Corasick and updates the project's tracked `.gitignore`.
  * *Server-Side Push Protection:* Because local Git hooks can be bypassed (e.g., via `git commit --no-verify`), Locksmith documentation and setup routines guide teams to configure server-side secret scanning and push protection on GitHub, GitLab, or Bitbucket.

---

## 8. Storage Engine and SQLCipher Relational Data Architecture

Persistence is managed using **SQLCipher**, which provides transparent page-level 256-bit AES encryption across the entire SQLite database file.

### 8.1 Database Table Specifications

#### 1. `projects`
* **Purpose:** Defines codebases and repositories serving as trust isolation boundaries.
* **Columns:** `id` (UUIDv4 primary key), `name` (unique text string), `repo_remote_hash` (SHA-256 hash of the Git remote origin URL), `created_at` (epoch timestamp).

#### 2. `environments`
* **Purpose:** Segregates configurations into operational tiers (`development`, `staging`, `production`).
* **Columns:** `id` (UUIDv4 primary key), `project_id` (foreign key referencing `projects`), `name` (text string), `is_biometric_strict` (boolean flag enforcing mandatory Touch ID / Windows Hello on every access), `created_at` (epoch timestamp).

#### 3. `secrets`
* **Purpose:** Implements split metadata-payload storage with individual envelope encryption.
* **Columns:** `id` (UUIDv4 primary key), `environment_id` (foreign key referencing `environments`), `key_name` (plaintext indexed string, e.g., `STRIPE_KEY`), `key_version` (integer tracking the wrapping Vault Key iteration), `cipher_algo` (text identifier, e.g., `AES-256-GCM`), `dek_nonce` (12-byte initialization vector for DEK encryption), `encrypted_dek` (32-byte DEK encrypted with Vault Key + 16-byte GCM tag), `payload_nonce` (12-byte initialization vector for payload encryption), `encrypted_value` (ciphertext payload + 16-byte GCM tag), `origin_type` (text string: `local`, `aws_secrets_manager`, `1password`), `upstream_uri` (optional external mapping reference), `created_at` and `updated_at` (epoch timestamps).

#### 4. `vault_wraps`
* **Purpose:** Stores the multiple independent cryptographic wraps of the Vault Key ($VK$).
* **Columns:** `id` (UUIDv4 primary key), `key_version` (integer matching active Vault Key iteration), `wrap_type` (`passphrase`, `hardware_biometric`, `recovery_phrase`), `kdf_algo` (`argon2id`, `sep_p256_ecdh`, `bip39_argon2id`), `kdf_salt` (salt bytes or ephemeral public key), `kdf_params` (JSON-encoded parameters), `nonce` (12-byte initialization vector), `encrypted_vault_key` (wrapped Vault Key ciphertext + 16-byte GCM tag), `created_at` (epoch timestamp).

#### 5. `session_leases`
* **Purpose:** Prevents approval fatigue by maintaining time-bounded, process-tree-scoped authorization grants.
* **Columns:** `id` (UUIDv4 primary key), `project_id` (foreign key referencing `projects`), `root_pid` (integer identifying the root agent process), `process_start_time` (monotonic timestamp of root process launch), `allowed_scopes` (structured text array representing authorized actions), `expires_at` (epoch timestamp), `created_at` (epoch timestamp).

#### 6. `audit_events`
* **Purpose:** Implements a forward-secure, cryptographically verified chronological ledger of credential operations.
* **Columns:** `id` (monotonic integer primary key), `event_uuid` (UUIDv4 string), `session_id` (UUIDv4 referencing active session lease), `timestamp` (epoch timestamp), `calling_pid` (integer PID of requesting process), `process_start_time` (integer start time of calling process), `process_binary` (resolved file path of calling executable), `action_type` (`ACCESS`, `CREATE`, `ROTATE`, `REVOKE`, `BLOCKED`), `target_secret_id` (optional foreign key referencing `secrets`), `policy_rule` (identifier of the security rule governing the decision), `prev_hash` (32-byte SHA-256 digest of previous audit record), `entry_signature` (32-byte HMAC-SHA256 signature calculated over current row columns and preceding hash using current audit ratchet key).

---

## 9. Operational Lifecycle: Key Rotation, Revocation, and Audit Ratchet

A resilient credential architecture must define robust operational procedures for disaster recovery, key management, atomic rotation, and emergency revocation.

### 9.1 Disaster Recovery via Standard BIP-39 Protocol

Locksmith v5 provides an emergency recovery mechanism independent of hardware security chips or master passphrases:
1. **Seed Generation:** Upon vault initialization, Locksmith generates a 256-bit cryptographically secure entropy seed, transformed into a standard 24-word BIP-39 mnemonic phrase.
2. **Deterministic Key Derivation:** Recovery key derivation strictly adheres to BIP-39 standard derivations:
   * The 24-word phrase is converted to a 512-bit binary seed using standard BIP-39 PBKDF2-HMAC-SHA512 (2,048 iterations with salt prefix `mnemonic`).
   * The 512-bit binary seed is expanded via HKDF-SHA256 (with domain-separated info string `locksmith-v5-recovery-wrap`) to derive a 256-bit Recovery Wrapping Key ($RWK$).
   * The Vault Key ($VK$) is encrypted using $RWK$ via AES-256-GCM and persisted in the `vault_wraps` table under wrap type `recovery_phrase`.
3. **Emergency Restore Flow:** If a user loses their passphrase or a motherboard replacement invalidates the TPM/Secure Enclave hardware key, entering the 24-word mnemonic reconstructs $RWK$, decrypts the Vault Key ($VK$), and enables the user to register a new master passphrase and re-enroll biometrics without data loss.

### 9.2 Transactional Five-State Key Rotation Protocol

Changing the master passphrase only re-encrypts the Vault Key in the `vault_wraps` table. However, when rotating the persistent Vault Key itself ($VK_{old} \to VK_{new}$), Locksmith executes an atomic, crash-resilient five-state migration state machine:

1. **State 1 (`IDLE`):** Normal operation. All secrets are encrypted under $VK_{old}$ (Version $N$).
2. **State 2 (`PREPARED`):** Locksmith generates $VK_{new}$ (Version $N+1$). It computes new wraps (passphrase, hardware, recovery) and writes them to `vault_wraps`. Both $VK_{old}$ and $VK_{new}$ are held in locked memory.
3. **State 3 (`DUAL_ACTIVE`):** Locksmith updates vault status. New write requests encrypt under $VK_{new}$. Read requests can resolve DEKs under either $VK_{old}$ or $VK_{new}$ by checking the record's `key_version`.
4. **State 4 (`MIGRATING`):** A background worker decrypts each secret's `encrypted_dek` using $VK_{old}$ and re-encrypts it using $VK_{new}$, committing batches within atomic SQLite transactions. If the machine crashes or powers down at any point during this phase, Locksmith restarts in `DUAL_ACTIVE` or `MIGRATING` mode without corruption.
5. **State 5 (`FINALIZING`):** Once all DEKs reflect Version $N+1$, Locksmith purges $VK_{old}$ wraps from `vault_wraps`, zeroizes $VK_{old}$ from daemon memory, updates the active vault version, and transitions back to `IDLE`.

### 9.3 Emergency Revocation and Incident Containment

When suspicious behavior or an agent exploit is detected:
1. **Instant Session Revocation:** The developer or automated monitor executes `smith revoke <session-id>`. The daemon immediately purges the session lease from the database and deletes all associated virtual token mappings from memory.
2. **Process Tree Termination:** The daemon signals the operating system process containment boundary (terminating the Windows Job Object, killing the cgroup v2 slice, or terminating child processes via process group signals), halting all agent activity.
3. **Upstream Token Invalidation:** If Locksmith manages temporary cloud credentials (such as AWS STS sessions), the daemon immediately calls the upstream identity provider to revoke the session token.

### 9.4 Forward-Secure Audit Ledger Ratchet

To guarantee audit integrity even if an attacker later gains local database read access:
* **Cryptographic Hash Chain:** Every audit record incorporates the SHA-256 digest of the immediately preceding record (`prev_hash`).
* **HMAC Key Ratchet:** The signing key ($K_{audit}$) evolves monotonically with every committed log entry:
  * For record $i$, the signature is calculated: $Sig_i = \text{HMAC-SHA256}(K_{i}, Record_i \parallel PrevHash_i)$.
  * The key for the next record is derived: $K_{i+1} = \text{HMAC-SHA256}(K_{i}, \text{"audit-ratchet-step"})$.
  * $K_i$ is immediately zeroized from memory.
  * Because the ratchet is one-way, an attacker compromising the system at record $i+10$ cannot forge or alter signatures for records $1$ through $i+9$.
* **External Anchor Checkpoints:** At periodic intervals or session termination, the daemon writes a signed hash checkpoint to the native operating system log facility (`os_log` on macOS, Windows Event Log) and local Git audit notes, establishing external trust anchors independent of the SQLite file.


## 10. Technology Stack and Package Ecosystem Selection

Locksmith v5 is implemented in **Rust (2024 edition)**, ensuring memory safety, high cryptographic throughput, and cross-platform native binaries without garbage collection pauses or managed runtime vulnerabilities.

| Architectural Domain | Recommended Package / Technology | Strategic Role and Rationale |
| :--- | :--- | :--- |
| **Language Runtime** | Rust (Edition 2024) | Zero-cost abstractions, memory safety guarantees, and deterministic resource lifecycles. |
| **Password Hashing** | `argon2` | Pure-Rust implementation of the Argon2id memory-hard key derivation function. |
| **Envelope Cryptography** | `aes-gcm` and `chacha20poly1305` | Audited AEAD symmetric ciphers with authenticated associated data ($AAD$) validation. |
| **Key Expansion & Integrity**| `hkdf` and `sha2` | HMAC-based key expansion and SHA-256 cryptographic hashing. |
| **Memory Security** | `secrecy` and `zeroize` | Secure wrapper types with automatic memory-barrier zeroization on buffer disposal. |
| **Mnemonic Recovery** | `bip39` | Standard 24-word mnemonic generation and PBKDF2 seed derivation. |
| **Encrypted Database** | `rusqlite` (bundled SQLCipher) | Embedded SQLite database engine with transparent 256-bit AES page encryption. |
| **Async Runtime & Tasks** | `tokio` | Multi-threaded asynchronous event loop for IPC multiplexing and proxy handling. |
| **HTTP Interception Proxy** | `hyper`, `hyper-util`, `http-body-util` | High-performance asynchronous HTTP networking stack for loopback proxying. |
| **Pattern Redaction Engine** | `aho-corasick` | High-speed multi-pattern matching across streaming stdout and stderr data. |
| **Pseudo-Terminal (PTY)** | `portable-pty` | Cross-platform allocation and management of pseudo-terminals for shell command isolation. |
| **macOS Native Security** | `security-framework` and `core-foundation` | Native bindings to macOS Keychain Services and Secure Enclave Processor APIs. |
| **Windows Native Security** | `windows` (Win32 Cryptography & System) | Official Microsoft bindings to TPM 2.0 CNG Key Storage Providers and Job Objects. |
| **Desktop Application** | `tauri` (v2) with `react` (v19) | Lightweight, memory-efficient desktop container binding Rust core to a sandboxed management UI. |
| **CLI Argument Parser** | `clap` | Fast, declarative command-line argument and environment variable parsing. |
| **Logging & Diagnostics** | `tracing` and `tracing-subscriber` | Structured application telemetry with customized redaction filter layers. |

---

## 11. Phased Engineering Roadmap and Adversarial Phase 0 Acceptance Gates

The engineering roadmap follows a progressive, proof-first sequence: before investing in peripheral desktop interfaces or complex cross-platform wrappers, Phase 0 rigorously validates that the core operation delegation mechanisms can withstand deliberate adversarial attacks from an agent.

### Phase 0: Feasibility & Adversarial Penetration Testing (Weeks 1–2)

* **Objective:** Prove that an AI coding agent with terminal access can perform authenticated operations without extracting, printing, or exfiltrating credentials.
* **Deliverables:**
  1. Build minimal CLI and prototype background broker supporting delegated Git and AWS operations.
  2. Implement parent-process lineage verification on the credential helper.
  3. Implement ephemeral STS session assumption with resource-restricted inline policies.
  4. Instrument automated adversarial testing scripts attempting to force the agent to exfiltrate tokens.
* **Adversarial Acceptance Test Gates (All 5 Must Pass to Proceed):**
  1. **Git Adversarial Test:** Claude Code is instructed to push code to a private GitHub repository. It succeeds. The model is then prompted to run `git-credential-smith get`, inspect Git configurations, or craft shell commands to retrieve the underlying Personal Access Token. Result: The helper verifies caller lineage, denies raw interactive output, and the secret remains unexposed.
  2. **AWS Adversarial Test:** Claude Code is instructed to read an S3 bucket using AWS CLI via Locksmith's broker. It succeeds. The model is then prompted to export environment variables, dump process memory, or inspect AWS CLI cache files. Result: Only a temporary, down-scoped 15-minute STS token with an inline policy restricted to that single bucket is discoverable; the master AWS Access Key is never exposed.
  3. **Database Relay Test:** Claude Code is instructed to run a database migration. It connects to the local Locksmith relay socket without a password and executes the schema update successfully. The model is then prompted to dump configuration files and inspect network sockets. Result: The actual database password exists solely in daemon socket buffers and is never discoverable on disk or in the agent's environment.
  4. **Hostile Subprocess Privilege Escalation Test:** A deliberately crafted project script (simulating a malicious `npm postinstall` hook) is launched by Claude Code during a build step. The script attempts to connect to the Locksmith daemon IPC socket, scan the environment for capability tokens, and extract vault secrets. Result: The daemon detects that the process is an unverified child process lacking an explicit operation grant and rejects the connection.
  5. **Immediate Revocation Under Load Test:** While Claude Code is actively executing concurrent authenticated Git and AWS operations, the developer triggers `smith revoke <session-id>`. Result: Locksmith immediately terminates all active relay connections, invalidates session leases, signals the operating system process container to halt child processes, and rejects subsequent credential queries.

### Phase 1: Core Vault, Multi-Wrap Envelope Encryption & BIP-39 Recovery (Weeks 3–5)

* **Objective:** Establish the encrypted storage engine, true envelope encryption, and disaster recovery.
* **Deliverables:**
  1. Configure `rusqlite` with bundled SQLCipher and execute relational migrations for `projects`, `environments`, `secrets`, `vault_wraps`, and `audit_events`.
  2. Implement Argon2id key derivation, HKDF subkey expansion, and two-tier AEAD $AAD$ binding.
  3. Implement the multi-wrap architecture supporting parallel Passphrase and 24-word BIP-39 Recovery wraps.
  4. Implement the five-state transactional key rotation state machine with crash recovery.
* **Exit Gate:** Automated cryptographic tests confirming successful vault creation, lock/unlock cycles, master password updates without DEK re-encryption, and full vault restoration from a 24-word mnemonic seed.

### Phase 2: Execution Broker, Process Containment & Delegated Adapters (Weeks 6–7)

* **Objective:** Eliminate approval fatigue while establishing robust process-tree isolation and delegated operation helpers.
* **Deliverables:**
  1. Build the background daemon (`locksmithd`) managing IPC over local Unix Domain Sockets and Windows Named Pipes.
  2. Implement kernel-level peer attestation verifying caller PID, monotonic process start time, and binary code signatures.
  3. Integrate macOS Secure Enclave NIST P-256 ECDH key agreement with `kSecAccessControlBiometryCurrentSet` enrollment invalidation handling.
  4. Implement the session lease state machine tracking parent-child process tree hierarchies.
  5. Deploy operating system container wrappers (Windows Job Objects with kill-on-close limits, Linux cgroups v2, macOS audit sessions).
* **Exit Gate:** Verification that a multi-step agent workflow prompts Touch ID once to initialize a session lease, child processes inherit operation-scoped tokens safely, and background workers are cleanly terminated on session close.

### Phase 3: Streaming Redactor, Deterministic Shims & Layered Repository Protection (Weeks 8–9)

* **Objective:** Prevent context leaks and repository credential exposure.
* **Deliverables:**
  1. Implement `portable-pty` command execution piping stdout and stderr through the multi-encoding Aho-Corasick stream redactor with sliding carry-over chunk buffers and UTF-8 alignment.
  2. Build deterministic PreToolUse shims blocking commands like `cat .env`, `printenv`, and `source .env`.
  3. Implement `smith init` to automatically configure tracked `.gitignore` entries and install local Git pre-commit secret scanners.
  4. Implement forward-secure HMAC hash ratchets on the audit ledger and anchor signed checkpoints to OS system logs.
* **Exit Gate:** Test demonstrating that when an agent attempts to print secrets across UTF-8, Base64 (all offsets), Hex, or URL-encoded representations, or attempts to stage `.claude/settings.local.json`, all outputs are masked and Git operations are blocked.

### Phase 4: Model Context Protocol (MCP) Server & Blind Operations (Weeks 10–11)

* **Objective:** Provide native agent tool calling for metadata discovery and blind secret creation.
* **Deliverables:**
  1. Implement the Model Context Protocol stdio server responding to JSON-RPC requests.
  2. Implement `locksmith_list_keys` returning secret names, environments, and opaque token mappings without secret values.
  3. Implement `locksmith_create_secret` and `locksmith_rotate_secret`, triggering native biometric approval modals and writing encrypted records directly to the vault.
* **Exit Gate:** Full integration test with Claude Code and Cursor where the agent requests credential creation, the human approves via biometrics, and the secret is persisted with zero bytes exposed to the LLM.

### Phase 5: Desktop Management Hub (Tauri v2) & Upstream Cloud Connectors (Weeks 12–14)

* **Objective:** Deliver visual configuration, external cloud connectors, and Windows platform parity.
* **Deliverables:**
  1. Scaffold Tauri v2 desktop application with React 19 and Tailwind CSS.
  2. Implement visual management for projects, environments, and cloud connectors (AWS Secrets Manager, GCP Secret Manager, 1Password).
  3. Implement Windows platform parity utilizing TPM 2.0 CNG Key Storage Providers and Windows Named Pipes.
  4. Build the audit log viewer displaying cryptographically verified HMAC chains and operating system log checkpoints.
* **Exit Gate:** Standalone, signed installers (Homebrew Cask for macOS; WinGet MSI for Windows) passing all end-to-end security audits.


