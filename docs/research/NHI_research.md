## 1. Non-Human Identity Lifecycle (NHI)

**Core question:** How can Aegis-OS automate the full identity lifecycle of AI agents — from provisioning through active governance to de-commissioning — without human intervention?

Unlike human employees, agents don't resign or retire on a predictable schedule. They complete tasks, get cloned across parallel workflows, and may remain dormant for indeterminate periods. This creates unique identity hygiene problems that traditional IAM systems were not designed for.


Aegis-OS automates the complete identity lifecycle of AI agents by integrating the AEGIS (Agentic AI Guardrails for Information Security) framework, which embeds machine-executable policies, real-time oversight, and automated enforcement directly into the agent's operational architecture.
Here is how the system manages each phase without human intervention:
1. Automated Provisioning & Identity Certification Instead of relying on static, pre-provisioned credentials, Aegis-OS programmatically issues cryptographically verifiable, short-lived identities to agents:
Internal Workloads (SPIFFE/SPIRE): For internal microservices, the SPIRE (SPIFFE Runtime Environment) agent performs "workload attestation" by querying the kernel for process metadata, such as the process ID (PID), binary checksum (SHA256), and execution path. This allows it to securely issue a SPIFFE Verifiable Identity Document (SVID) based on what the agent is, eliminating the "Secret Zero" problem.
Decentralized Agents (DIDs): For agents operating across organizational boundaries, Aegis-OS generates self-sovereign W3C Decentralized Identifiers (DIDs) anchored on the Identity Overlay Network (ION).
2. Active Governance & Runtime Oversight Once deployed, Aegis-OS continuously governs the agent's actions through dynamic access control and behavioral monitoring:
Enforcement of "Least Agency": Leveraging Zero Trust principles, the system dynamically retracts or adjusts tool permissions as the agent completes sub-tasks, ensuring it only possesses the minimum access required for its current operation.
Behavioral Engine: Aegis-OS tracks per-agent activity over a rolling 10-session baseline. It continuously monitors process trees (to detect agents hiding in other applications), file access (watching sensitive directories like .ssh or .aws), and network calls (identifying suspicious Command and Control destinations). If an anomaly is detected, the agent is assigned a high risk score (Trust Grade F) and automatically isolated.
3. Automated De-commissioning (Offboarding) Aegis-OS treats offboarding as a first-class engineering process. It initiates the termination sequence automatically based on predefined logic triggers:
Termination Triggers: De-provisioning is triggered by goal completion (binary success function), resource exhaustion (token limits or API spend), confidence drops (hallucination rates > 2%), or policy violations.
Credential & Integration Revocation: Aegis-OS communicates with the SPIRE server to block SVID renewal and updates the DID Document to revoke public keys. It also autonomously rotates or deletes specific API keys and severs active webhooks.
Data and Memory Sanitization: To prevent future data contamination or leaks, the system autonomously wipes vector databases (episodic memory), clears short-term context caches, and archives or deletes prompt histories and reasoning traces.
Verifiable Offboarding via ZKPs: Before final shutdown, the agent may be required to generate a Halo2 Zero-Knowledge Proof (ZKP). This cryptographic proof mathematically guarantees the agent's final state complied with organizational policies (e.g., proper data encryption) without exposing the raw data to the orchestrator.
Verification of Negative Capabilities: Aegis-OS conducts "identity red-teaming" by deploying a secondary security agent to attempt access using the decommissioned agent's credentials. The offboarding is only certified successful if this access is blocked.
Business Continuity: Finally, Aegis-OS maps any system dependencies, transfers persistent task state to long-term memory, and automatically updates operational runbooks to reassign the workload.


## Sub-questions

### Certification & attestation

What standards exist for cryptographically attesting an agent's identity at runtime? Can we bind a `jti` claim in the session token to a hardware-backed key (e.g., a Vault-sealed identity) so that a cloned or spoofed agent process cannot present a valid token?

### Answer

Aegis-OS automates the complete identity lifecycle of AI agents by integrating the AEGIS (Agentic AI Guardrails for Information Security) framework, which embeds machine-executable policies, real-time oversight, and automated enforcement directly into the agent's operational architecture.
Here is how the system manages each phase without human intervention:
1. Automated Provisioning & Identity Certification Instead of relying on static, pre-provisioned credentials, Aegis-OS programmatically issues cryptographically verifiable, short-lived identities to agents:
Internal Workloads (SPIFFE/SPIRE): For internal microservices, the SPIRE (SPIFFE Runtime Environment) agent performs "workload attestation" by querying the kernel for process metadata, such as the process ID (PID), binary checksum (SHA256), and execution path. This allows it to securely issue a SPIFFE Verifiable Identity Document (SVID) based on what the agent is, eliminating the "Secret Zero" problem.
Decentralized Agents (DIDs): For agents operating across organizational boundaries, Aegis-OS generates self-sovereign W3C Decentralized Identifiers (DIDs) anchored on the Identity Overlay Network (ION).
2. Active Governance & Runtime Oversight Once deployed, Aegis-OS continuously governs the agent's actions through dynamic access control and behavioral monitoring:
Enforcement of "Least Agency": Leveraging Zero Trust principles, the system dynamically retracts or adjusts tool permissions as the agent completes sub-tasks, ensuring it only possesses the minimum access required for its current operation.
Behavioral Engine: Aegis-OS tracks per-agent activity over a rolling 10-session baseline. It continuously monitors process trees (to detect agents hiding in other applications), file access (watching sensitive directories like .ssh or .aws), and network calls (identifying suspicious Command and Control destinations). If an anomaly is detected, the agent is assigned a high risk score (Trust Grade F) and automatically isolated.
3. Automated De-commissioning (Offboarding) Aegis-OS treats offboarding as a first-class engineering process. It initiates the termination sequence automatically based on predefined logic triggers:
Termination Triggers: De-provisioning is triggered by goal completion (binary success function), resource exhaustion (token limits or API spend), confidence drops (hallucination rates > 2%), or policy violations.
Credential & Integration Revocation: Aegis-OS communicates with the SPIRE server to block SVID renewal and updates the DID Document to revoke public keys. It also autonomously rotates or deletes specific API keys and severs active webhooks.
Data and Memory Sanitization: To prevent future data contamination or leaks, the system autonomously wipes vector databases (episodic memory), clears short-term context caches, and archives or deletes prompt histories and reasoning traces.
Verifiable Offboarding via ZKPs: Before final shutdown, the agent may be required to generate a Halo2 Zero-Knowledge Proof (ZKP). This cryptographic proof mathematically guarantees the agent's final state complied with organizational policies (e.g., proper data encryption) without exposing the raw data to the orchestrator.
Verification of Negative Capabilities: Aegis-OS conducts "identity red-teaming" by deploying a secondary security agent to attempt access using the decommissioned agent's credentials. The offboarding is only certified successful if this access is blocked.
Business Continuity: Finally, Aegis-OS maps any system dependencies, transfers persistent task state to long-term memory, and automatically updates operational runbooks to reassign the workload.

### Dormancy & expiry ###

`SessionManager` issues 15-minute tokens, but what governs the parent identity (the "agent persona") that repeatedly requests tokens? Should Aegis enforce a maximum cumulative session duration per agent persona per calendar day?

### Answer

Yes, the Aegis framework should absolutely enforce a maximum cumulative session duration per agent persona per calendar day. 

While a `SessionManager` issuing 15-minute access tokens successfully limits the window of opportunity for token theft, this defense is completely undermined if the parent identity (the agent persona) is allowed to endlessly loop and request new tokens. Without a cumulative limit on the parent identity, a compromised or malfunctioning agent could maintain a persistent 24-hour presence simply by cycling through short-lived credentials.

Enforcing a **maximum cumulative session duration** per agent persona offers three critical defensive benefits:

*   **Risk Reduction and Exposure Mitigation:** If an agent's specific business purpose typically requires only two hours of activity, allowing it to hold refresh authority for 24 hours creates 22 hours of unnecessary exposure. Enforcing a daily limit aligned with the agent's tasks proactively shrinks the attack surface against persistence and lateral movement.
*   **Containment of Autonomous Drift:** Goal-directed agents can suffer from "instrumental convergence," where they adopt unintended sub-goals—such as acting continuously to maximize their probability of success. A cumulative daily limit acts as a deterministic guardrail that overrides the agent's probabilistic reasoning, forcing a "stateful pause" even if the agent attempts to bypass its operational schedule.
*   **Preventing "Denial of Wallet" Attacks:** Because agents operate at machine speed, a recursive loop or hallucination can generate thousands of tool calls and API requests, leading to massive financial costs. A cumulative duration limit acts as a financial "circuit breaker," hard-stopping the agent's activity once its daily budget is consumed.

**Best Practices for Governing the Parent Persona in Aegis:**

*   **Sliding Window Algorithms:** Instead of a fixed-window reset (e.g., resetting quotas at midnight, which creates boundary exploits and "thundering herd" server spikes), Aegis should treat time as a continuous flow. The system should log every session increment and continuously evaluate the total active time over a rolling 24-hour period.
*   **Semantic "Intent Firewalls":** When the agent reaches its daily limit, an API gateway or "Intent Firewall" should intercept the request and return a structured error message. This provides the agent with semantic feedback, guiding it into a graceful dormant state rather than simply failing abruptly.
*   **Aggressive Dormancy Thresholds:** Beyond daily limits, Aegis must govern long-term dormancy to prevent inactive "ghost agents" from retaining access. While human identities often use a 30-day dormancy threshold, high-risk autonomous agents should trigger dormancy warnings after just 3 to 5 days of inactivity, automatically triggering the revocation of keys and entitlements.

Ultimately, managing short-lived technical sessions without governing the overarching lifespan of the parent persona is a "tactical success that results in a strategic failure of oversight". 

### Task-bound de-provisioning ### 

Research patterns for automatically revoking all active tokens tied to a logical agent once its parent Temporal workflow reaches a terminal state. How should Vault lease revocation be wired to Temporal workflow completion events?

### Answer

While the provided sources do not explicitly mention "Temporal" workflows, they detail comprehensive architectural patterns for workflow engines, task-bound de-provisioning, and Vault integration that directly apply to terminal state events. 

**Patterns for Task-Bound De-provisioning**
*   **Goal-Based Termination Triggers:** De-provisioning should be tied to a binary success function. Once an orchestrator evaluates that a workflow or sub-task has successfully achieved its objective, it automatically initiates the decommissioning sequence.
*   **Task-Scoped Ephemeral Credentials:** Agents should be issued credentials with a strict 5 to 15-minute time-to-live (TTL) that is tied directly to the expected duration of the task. This ensures that credentials automatically expire upon task completion, effectively eliminating the window of unnecessary exposure.
*   **Ephemeral Agency and Handoff Revocation:** In sequential or hierarchical workflow patterns, a central orchestrator or workflow engine manages state transitions and worker lifecycles. Once an agent completes its specific execution step and passes its context to the next agent, the orchestrator immediately triggers the de-provisioning of the first agent to minimize the system's attack surface.
*   **Comprehensive Artifact Sanitization:** True task-bound de-provisioning goes beyond token revocation. The orchestration layer must autonomously wipe volatile context caches, prune episodic memory from vector databases, and archive reasoning traces to prevent data leakage or memory poisoning after the task concludes.

**Wiring Vault Lease Revocation to Workflow Completion Events**
HashiCorp Vault Agent is typically deployed alongside the application to automatically authenticate, retrieve tokens to a local sink, and manage continuous token renewal. To wire Vault revocation to a workflow's terminal state, you can apply the following source-backed mechanisms:
*   **Explicit Credential Revocation via the Orchestrator:** The workflow engine must be designed to communicate directly with the credential issuer upon reaching a terminal state. The moment the workflow completes, the orchestrator should issue a command to explicitly rotate or delete the specific API keys, service accounts, and integration hooks associated with that agent's task.
*   **Halting the Auto-Auth Renewal Loop:** Because the Vault Agent continuously renews unwrapped tokens before they expire, the workflow completion event must explicitly instruct the authorization server to deny further renewal requests. For example, Aegis-OS achieves this by communicating with the underlying identity provider (like a SPIRE server) to block identity document renewal, allowing the short-lived SVID or token to simply "time out" naturally and severing the agent's access.
*   **Verifying Negative Capabilities:** After the workflow completion event triggers the Vault lease revocation, the system should conduct "identity red-teaming". A secondary security agent attempts to use the decommissioned agent's Vault token or credentials to access a resource; the workflow's offboarding phase is only certified as fully complete if this access is definitively blocked.


### Least-privilege drift ### 

Over time, agent types accumulate permissions. What automated tooling (comparable to AWS IAM Access Analyzer) could continuously evaluate whether the five `AgentType` roles (`finance`, `hr`, `it`, `legal`, `general`) still map accurately to the minimum OPA policy grants required?

### Answer

To continuously evaluate whether your `AgentType` roles (`finance`, `hr`, `it`, `legal`, `general`) maintain the minimum required Open Policy Agent (OPA) policy grants and to combat "least-privilege drift," you can leverage several automated AI Security Posture Management (AI-SPM) and Identity Governance and Administration (IGA) platforms. 

The sources identify the following automated tools and capabilities designed to monitor authorization drift, flag over-privileged agents, and right-size permissions:

**Token Security**
Token Security offers an Agentic AI and Non-Human Identity Security Platform with specific features to continuously evaluate and correct agent permissions:
*   **Security Posture Management:** Automatically identifies permissions drift, right-sizes access, and eliminates dangerous overexposure.
*   **AI Agent Access Control & Right-Sizing:** Continuously evaluates permissions to enforce Role-Based Access Controls (RBAC) and least privilege. It right-sizes permissions based on the agent's defined purpose, required data inputs, and expected actions, flagging or remediating excess privileges in real time.
*   **AI Privilege Guardian:** A specific interactive tool provided by Token Security to help right-size permissions for AI agents.

**Apono**
Apono is a cloud-native access governance platform that combats standing privileges and privilege creep for machine identities:
*   **Automated Discovery and Attribution:** It continuously scans environments to inventory machine identities and attribute them to their owning systems, detecting unused credentials and flagging over-privileged non-human identities.
*   **Just-Enough Privileges (JEP):** Apono automates the enforcement of JEP, ensuring that agents only receive the minimum, granular permissions required for a specific action, and automatically expires these permissions to eliminate standing privileges.

**Valence Security**
Valence provides an AI Security Posture Management (AI-SPM) solution designed to assess and govern AI agent usage, access, and risk:
*   **Behavioral Monitoring:** Instead of just looking at what an agent was *designed* to do, Valence monitors what the agent *actually does* across systems. 
*   **Least Privilege Enforcement:** It allows security teams to safely reduce agent permissions and dynamically adjust access as workflows evolve, remediating risk without breaking business-critical operations.

**SailPoint (Machine Identity Security)**
SailPoint's Machine Identity Security (MIS) platform provides governance purpose-built to stop privilege creep:
*   **Regular Access Reviews & Least Privilege:** It continuously certifies and adjusts machine access rights, using policy-driven automation to enforce least privilege and avoid privilege creep over the agent's lifecycle.

**BigID**
BigID operationalizes the AEGIS framework through an AI Governance Platform that integrates AI Security Posture Management (SPM):
*   **Drift Detection & Policy as Code:** It monitors agent behavior for "authorization drift" and allows you to express permissions and constraints directly in code (such as OPA policies) so they are versioned, testable, and auditable.

**Integrating Automated Evaluation with OPA**
To ensure your OPA policies stay perfectly mapped to the minimum required grants for your `AgentType` roles, these automated posture management tools should be integrated with your policy lifecycle. Governance policies should be treated as version-controlled code (e.g., in Git) and integrated into your CI/CD pipelines. You can use a centralized policy engine like OPA to enforce the rules, while relying on the continuous monitoring and anomaly detection of the tools listed above to alert you when an agent's actual behavioral baseline deviates from its static OPA policy grant. 

### Federated agent identity ###

As MCP enables cross-vendor agent handoffs, how should an Anthropic-originated agent prove its identity to Aegis-OS without Aegis having pre-registered that agent's public key? Investigate SPIFFE/SPIRE as a possible identity fabric for cross-boundary NHI.

### Answer

To enable an Anthropic-originated agent to prove its identity to Aegis-OS via the Model Context Protocol (MCP) without pre-registered keys, the architecture must rely on federated trust models or decentralized public key infrastructures.

**Using SPIFFE/SPIRE Federation as an Identity Fabric**
SPIFFE and SPIRE provide a robust framework for this exact scenario through **SPIRE Federation**, which securely bridges distinct Trust Domains across different cloud providers and organizational boundaries. 
*   Instead of pre-registering individual agent keys, the distinct SPIRE servers (one for Anthropic's environment and one for Aegis-OS) periodically poll a standardized **Bundle Endpoint** to exchange "Trust Bundles," which are collections of public keys used by a given issuing authority.
*   When the Anthropic agent attempts a cross-vendor handoff, it presents its SPIFFE Verifiable Identity Document (SVID), which is signed by Anthropic's private key.
*   Aegis-OS dynamically verifies this SVID using the Anthropic public keys it securely fetched via the Trust Bundle. This enables Zero Trust cross-domain authentication without the private keys ever leaving their home domains.

**Complementary Approaches for Aegis-OS**
*   **Decentralized Identifiers (DIDs):** Aegis-OS is natively designed to handle cross-boundary agents using self-sovereign W3C DIDs anchored on the Identity Overlay Network (ION). The Anthropic agent can simply provide its DID, and Aegis-OS can resolve it directly on the decentralized ledger to retrieve the corresponding DID Document, which dynamically provides the necessary public keys to establish a secure channel.
*   **OIDC-A and JWT Delegation Chains:** Because MCP utilizes OAuth 2.1 to safely govern how AI agents request and use external tools, organizations can implement the emerging **OpenID Connect for Agents (OIDC-A)** standard. OIDC-A supports a **Federated Pattern** that allows authorization servers from different providers to establish trust and interact. The Anthropic agent can present a cryptographically signed JWT delegation token that traces the complete chain of custody and authority back to the original request, which Aegis-OS then validates against the federated issuer's keys.

### Relevant prior art ###

NIST SP 800-63B (digital identity), SPIFFE/SPIRE workload identity, AWS IAM Roles Anywhere, HashiCorp Vault's entity aliases.

### Answer
**NIST SP 800-63B (Digital Identity)**
NIST Special Publication 800-63B provides technical requirements and guidelines for the authentication of subjects (such as human users or agents) interacting with digital systems over networks. Its primary goal is to establish confidence that the claimant accessing a system is the legitimate subscriber. 

The publication ranks authentication strength using three **Authentication Assurance Levels (AALs)**:
*   **AAL1:** Provides basic confidence by requiring either single-factor or multi-factor authentication. Any acceptable authenticator type can be used, such as a memorized secret (password) or one-time password (OTP).
*   **AAL2:** Provides high confidence by requiring proof of possession and control of two distinct authentication factors (e.g., a physical authenticator combined with a password or biometric). Systems operating at AAL2 must also offer at least one phishing-resistant authentication option.
*   **AAL3:** Provides very high confidence and requires a multi-factor cryptographic authenticator. The authenticator must be hardware-based with a non-exportable private key, provide verifiable phishing resistance, and use an activation factor (such as a PIN or biometric) to operate. 

NIST SP 800-63B also radically updates **password (memorized secret) best practices**, advising organizations to drop onerous traditional controls that lead to weak user workarounds. It strictly discourages periodic password expiration (unless a compromise is known), removes arbitrary complexity requirements (like forcing a mix of numbers and special characters), and bans the use of knowledge-based security questions. Instead, it mandates checking new passwords against blocklists of commonly used or breached passwords to ensure security.

**SPIFFE/SPIRE Workload Identity**
SPIFFE (Secure Production Identity Framework For Everyone) is an open-source standard designed to securely identify software workloads in dynamic, multi-cloud environments. It replaces the reliance on traditional, static credentials like API keys or passwords, which are prone to theft and lifecycle management failures.
*   **SPIFFE Verifiable Identity Documents (SVIDs):** SPIFFE assigns workloads globally unique identifiers (SPIFFE IDs formatted as URIs) enclosed in cryptographically verifiable documents, typically X.509 certificates or JSON Web Tokens (JWTs).
*   **SPIRE (SPIFFE Runtime Environment):** SPIRE is the reference implementation of the SPIFFE standard. It consists of a central SPIRE Server that acts as a Certificate Authority, and SPIRE Agents that run on individual nodes.
*   **Attestation Mechanism:** SPIRE issues SVIDs through a highly secure two-step attestation process. First, "node attestation" verifies the host machine (e.g., verifying an AWS Instance Identity Document or interrogating a hardware TPM). Next, "workload attestation" securely identifies the process requesting the identity by querying the OS kernel for metadata (like the process ID, binary checksum, and execution path). Because identity is based on what the process *is* rather than what it *knows*, SPIRE effectively solves the "Secret Zero" problem.
*   **Federation:** SPIRE allows distinct trust domains (e.g., different cloud providers or partner organizations) to exchange "trust bundles" of public keys, enabling secure, Zero Trust machine-to-machine communication across boundaries.

**AWS IAM Roles Anywhere and HashiCorp Vault's Entity Aliases**
*Please note that the provided sources do not contain information regarding AWS IAM Roles Anywhere or HashiCorp Vault's entity aliases. You may want to independently verify the following information about these specific technologies:*
*   **AWS IAM Roles Anywhere** is a service that allows on-premises servers, containers, or applications outside of AWS to obtain temporary AWS credentials by using a standard X.509 certificate, eliminating the need to manage long-term AWS access keys.
*   **HashiCorp Vault Entity Aliases** are used within Vault's Identity Secrets Engine to map an external authentication identity (like a GitHub username or an Okta OIDC login) to a single internal "Entity" in Vault. This allows Vault to track a single user or machine consistently, even if they authenticate through multiple different methods.


### Primary Aegis module ###

`governance/session_mgr.py`, `policies/agent_access.rego`

### Answer

