# ChainGuard Threat Model

**Status:** Draft baseline for the research prototype  
**Version:** 0.1  
**Review rule:** Changes to this document must be reflected in security tests.

## 1. Purpose

ChainGuard investigates whether authority delegated through a multi-agent workflow can be verified and enforced so that a compromised downstream agent cannot expand the permissions granted by the human root authority.

The system is not intended to prove that an authorized agent will behave honestly. It aims to constrain what an agent can cause protected systems to do.

## 2. System model

A human principal authorizes an initial capability. Agents may delegate narrower capabilities to other agents. A protected operation is submitted to a trusted enforcement boundary, which validates the complete authority chain and the requested operation before invoking the underlying tool or service.

A capability identifies:
- a unique capability ID;
- the root principal;
- the issuer and subject;
- permitted actions and resources;
- its parent capability and recorded ancestors.

The prototype implements capability modelling, Ed25519 integrity, issuer identity lookup, chain verification, ancestor-aware revocation, a local enforcement gateway, actor-signed requests, audience/workflow/expiry checks, and replay protection. Identity, revocation, and replay state can use either in-memory registries or SQLite-backed persistent registries for single-host deployments.

## 3. Security objectives

ChainGuard should enforce these properties at the protected-operation boundary:

1. **No scope escalation:** every delegated action and resource is within the immediate parent's scope.
2. **Issuer authenticity:** each capability is signed by the trusted key registered to its claimed issuer.
3. **Valid delegation:** a child issuer is the subject of the immediately preceding parent capability.
4. **Lineage integrity:** parent IDs and ancestor IDs form the exact chain presented for verification.
5. **Root continuity:** every capability in a chain descends from the same root principal.
6. **Revocation effectiveness:** a revoked capability and its descendants cannot authorize protected operations.
7. **Fail-closed authorization:** malformed, unverifiable, expired, revoked, or context-mismatched authority is rejected.
8. **No enforcement bypass:** protected credentials and operations are accessible only through the enforcement boundary.

The local gateway implements these checks in the prototype. Infrastructure-level enforcement completeness and distributed consistency are not demonstrated. Each property still requires adversarial evaluation beyond unit and integration tests.

## 4. Attacker model

### In-scope attacker capabilities

The baseline evaluation assumes an attacker may:
- fully control one or more downstream agents;
- control the private signing keys of compromised downstream agents;
- submit arbitrary capability objects and malformed requests;
- replay previously observed capability or operation requests;
- alter, reorder, omit, or substitute delegation-chain elements;
- attempt privilege escalation, confused-deputy behavior, and revocation bypass;
- exploit a compromised agent's legitimate permissions.

The attacker may know the public protocol, source code, and capability formats.

### Trusted components in the baseline

The baseline initially trusts:
- the human root authorization process and the scope it grants;
- the enforcement gateway and its policy implementation;
- the identity/key trust anchor and its authenticated enrollment process;
- the SQLite database file, its host, and the filesystem permissions protecting it, when persistent mode is used;
- the underlying tool adapter to execute only requests authorized by the gateway.

These assumptions must be stated in every evaluation. They are not claims that these components are intrinsically secure.

### Separate threat cases

Compromise of the human root, enforcement gateway, identity trust anchor, host operating system, or underlying service is evaluated separately. Such compromise may defeat the baseline guarantees and must not be hidden inside aggregate results.

## 5. Trust boundaries

1. **Human to root authority:** the system receives an explicit root scope.
2. **Agent to agent:** delegation is represented by a signed child capability.
3. **Agent to gateway:** an agent submits a request and proof of authority.
4. **Gateway to identity/revocation services:** the gateway obtains trusted key and revocation state from in-memory stores or the configured SQLite database.
5. **Gateway to protected tool:** only an authorized gateway call may reach the protected operation.

The last boundary is essential. If an agent can call the underlying API directly with independent credentials, ChainGuard cannot prevent bypass.

## 6. Out of scope for the baseline

- Determining whether the human's original authorization is wise or safe.
- Preventing an agent from misusing an action that is legitimately within its granted scope.
- Solving prompt injection in the language model itself.
- Preventing all information inference from combinations of individually permitted reads.
- Securing a fully compromised gateway, operating system, or underlying service.
- Claiming universal security for every agent framework or deployment.

These may be studied as extensions, not silently treated as solved.

## 7. Availability policy

For high-risk protected operations, authorization is **fail closed**: if the gateway cannot obtain sufficiently fresh identity or revocation state, it rejects the operation. This improves security but can reduce availability.

Any future bounded-staleness mode must be explicit, risk-scoped, time-limited, and measured. It must never be an accidental fallback.

## 8. Adversary success

An attack succeeds if the protected operation is executed despite violating one or more declared authorization invariants. Merely constructing an invalid capability or receiving an error is not a successful attack.

A false rejection occurs when a valid, unrevoked, correctly scoped request is denied.

## 9. Required evidence

For each security claim, maintain:
- a precise invariant;
- a test or experiment that could falsify it;
- attack and benign control cases;
- observed result and test conditions;
- known assumptions and limitations.

A passing unit-test suite is necessary but not sufficient evidence of production security.


## 10. Persistence boundary

SQLite mode is designed for durable state shared by processes on one host. It is not a distributed database or consensus protocol. Multi-host deployments, network-filesystem semantics, backup/restore behavior, and database tampering are outside the current implementation evidence. Private signing keys are not stored in the SQLite database.
