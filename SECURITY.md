# Security Policy

## Project status

ChainGuard is an early-stage research prototype. It is not approved for protecting production accounts, funds, credentials, or sensitive data.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability, private key, credential, or sensitive operational detail in a public issue.

Use GitHub's **Report a vulnerability** flow on this repository if private vulnerability reporting is enabled. If that option is unavailable, contact the repository maintainer privately through their GitHub profile and ask for a secure reporting channel.

A useful report includes:
- the affected commit or version;
- the component and configuration;
- the security assumption being violated;
- minimal reproduction steps or a proof of concept;
- observed impact and expected behavior;
- any suggested mitigation.

Do not include real credentials, personal data, or third-party secrets. Use synthetic test data.

## Scope

Reports are especially useful for:
- unauthorized adapter execution;
- signature or identity verification bypass;
- delegation-chain or scope-escalation flaws;
- revocation or replay bypass;
- request-context or actor-authentication confusion;
- unsafe defaults or secret disclosure.

Availability issues and ordinary bugs are also welcome, but should be clearly distinguished from security vulnerabilities.

## Disclosure

Please allow the maintainer reasonable time to investigate and prepare a fix before public disclosure. No formal response-time or bug-bounty commitment is currently offered.
