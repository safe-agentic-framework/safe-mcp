# SAFE-T1506: INFRASTRUCTURE TOKEN THEFT

## Overview
**Tactic**: Credential Access (ATK-TA0006)  
**Technique ID**: SAFE-T1506  
**Severity**: High  

## Description
Infrastructure Token Theft refers to the unauthorized acquisition of authentication secrets used by backend systems, cloud infrastructure, or privileged internal services. Types of tokens typically stolen are: 
- Cloud API keys (AWS, Azure, GCP)
- Access tokens (OAuth, JWTs)
- Service account credentials
- CI/CD secrets (GitHub Actions tokens, GitLab CI variables)
- Container environment variables holding credentials
- Internal service-to-service auth tokens
- Secrets stored in configuration files, .env files, or logs

If an attacker compromises the MCP environment, they could steal these tokens and abuse them outside the normal LLM-tool context which could be in form of destruction of the cloud resources, access to internal APIs, extraction of private data, modification of Infrastructure as a Code (IaC), injection of malicious configurations, and movement laterally across the environments. 

Two of the most common token theft techniques Microsoft Detection and Response Team (DART) has observed have been through adversary-in-the-middle (AitM) frameworks or the utilization of commodity malware (which enables a ‘pass-the-cookie’ scenario).

## Attack Vectors
- **Primary Vector**: The attacker manipulates the LLM to call sensitive MCP tools, such as:
    - readFile()
    - listEnvironmentVariables()
    - readDatabaseConfig()
This gives the attacker the first foothold.
- **Secondary Vectors**: 
 - Once the LLM executes the commands, the attacker captures the output containing the tokens or credentials. 
 - Using file listing tools to locate hidden secrets
 - Triggering failure states in MCP tool handlers
 - Using cloud SDK tools exposed within the environment

## Technical Details

### Prerequisites
- Token must exist in an accessible location
- An initial access vector must already be successful 
- Tokens must not be properly protected or encrypted
- The MCP server must expose tools that allow data access

### Attack Flow
1. **Reconnaissance**: Locate systems, services, or workflows where authentication tokens may be stored, transmitted, or logged.
2. **Initial Access – Gaining a Foothold**: Obtain access sufficient to view, intercept, or extract tokens.
3. **Token Discovery**: Find valid infrastructure or service tokens which may be discovered in env variables, application logs, CI/CD secret variables, cloud instance metadata services and many more.
4. **Token Exfiltration**: Transfer stolen tokens to attacker-controlled systems.
5. **Token Validation & Privilege Enumeration**: Confirm token validity and determine permissions.
6. **Privilege Abuse & Lateral Movement** 
7. **Persistence Establishment**
8. **Impact**


### Example Scenario
The attacker begins by identifying environments where infrastructure tokens are likely to be exposed, such as public or private source code repositories and CI/CD configurations. Keyword-based searches for common secret identifiers (e.g., API_KEY, TOKEN, AWS_ACCESS_KEY_ID) are used to understand the organization’s tooling and cloud provider without direct exploitation [MITRE ATT&CK – Reconnaissance, TA0043; GitHub Secret Scanning].

The attacker gains access by compromising a developer’s account through phishing, enabling authenticated access to private repositories and CI/CD configurations. This step does not require exploiting infrastructure vulnerabilities; instead, it leverages valid user access, which is a well-documented initial access technique [MITRE ATT&CK – Initial Access, TA0001].

While reviewing CI/CD pipeline logs and configuration files, the attacker identifies exposed environment variables containing an infrastructure access token. Such exposure often occurs due to misconfigured logging or debugging output, aligning with unsecured credential storage and application token theft techniques [MITRE ATT&CK – Unsecured Credentials, T1552; Steal Application Access Token, T1528].

The attacker copies the discovered token and transfers it to an attacker-controlled system. Since tokens are portable and self-contained, exfiltration can occur through normal encrypted channels without triggering security alerts, consistent with common exfiltration techniques [MITRE ATT&CK – Exfiltration, TA0010].

Using the stolen token, the attacker authenticates directly to cloud APIs to confirm validity and enumerate permissions. Because the token represents a legitimate identity, the activity appears as authorized access, aligning with abuse of valid accounts [MITRE ATT&CK – Valid Accounts, T1078].
After confirming the token has broad permissions, the attacker accesses cloud storage, deploys additional resources, and pivots to other services linked to the same identity. Over-privileged service accounts significantly increase the blast radius of token theft [MITRE ATT&CK – Lateral Movement, TA0008].

To maintain access, the attacker creates additional API keys or IAM users using the compromised token. This ensures continued access even if the original token is revoked, a classic persistence strategy in credential-based attacks.

Finally, the attacker achieves their objectives, which may include data exfiltration, cloud resource abuse, supply-chain compromise, or service disruption.


## Impact
- Confidentiality [High]: Stolen tokens can lead to unauthorized access to sensitive data, cloud resources, and internal services, resulting in significant data breaches and intellectual property theft.
- Integrity [High]: Attackers can modify data if not properly encrypted with sophisticated tools
Attackers may exploit token privileges to alter cloud resources, manipulate CI/CD pipelines, or inject malicious code into production environments. This compromises the reliability and trustworthiness of systems and software produced by the organization.
- Availability [Medium]: Although token theft does not always aim to disrupt services, attackers may intentionally or unintentionally impact availability by abusing infrastructure access. Availability impacts may escalate if attackers deploy destructive actions or if remediation efforts require system downtime.
 

## Detection
### Log Patterns to Watch For:
- Token usage outside normal operating hours
- Tokens used without a corresponding user login event
- Repeated API calls using the same token across different services
- Successful authentication using service accounts or API tokens from new IP addresses or unusual geolocations.
- Secrets printed in build or deployment logs
- Sudden access to pipeline secrets by unfamiliar users
- Tokens accessed without a matching code change or deployment
- New API keys or tokens created shortly after token usage
- Token usage followed by credential creation events
- IAM role changes initiated by non-human identities

### Behavioral Indicators
- Service accounts behaving like human users
- Single token accessing multiple unrelated services
- Rapid enumeration of resources (e.g., listing buckets, databases, repos)
- Creation of additional tokens or credentials shortly after initial access
- Changes to automation workflows or pipelines without approvals

### Monitoring Strategies
- Implement:
    - Automated secret scanning in repos and CI/CD
    - Policy-as-code for IAM permissions
    - Continuous monitoring for exposed credentials
- Detect long-lived or non-expiring tokens
- Detect long-lived or non-expiring tokens
- Establish normal behavior for:
    - Token frequency
    - Resource scope
    - Time-of-day usage
    - Network locations


## Mitigation
- Audit all cloud and container accounts to verify their necessity and to ensure that the permissions assigned are appropriate.
- Implement RBAC to ensure that users account have only the minimum necessary privileges. This reduces the risk of excessive permissions that could be exploited.
- Use of Cloud Access Security Broker (CASB) to to establish and enforce usage policies and manage user permissions on cloud applications. This helps to prevent unauthorized access to application access tokens.
- Take advantage of IP ranges to limit inbound connections to your systems to only known IP addresses.
- Disable Self-Consent: Restrict users from authorizing third-party apps via OAuth 2.0, preventing attackers from using malicious apps to steal tokens. 
- Reduce Token Lifespan: Set short expiration times for session tokens to minimize the window of opportunity for attackers to use stolen tokens.

## References
- [MITRE ATT&CK – Credential Access (T1552)](https://attack.mitre.org/techniques/T1552/)
- [Token tactics: How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/#:~:text=When%20Azure%20AD%20issues%20a,prevented%20from%20accessing%20organizational%20resources)
- [Token Theft in the Cloud: What It Is and How to Prevent It](https://www.csicorp.net/token-theft-in-the-cloud-what-it-is-and-how-to-prevent-it/#:~:text=How%20Does%20Token%20Theft%20Happen,%2C%20logs%2C%20or%20error%20messages)
- [Defending Against Prompt Injection With a Few DefensiveTokens](https://arxiv.org/html/2507.07974v1)
- [Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [Strategies used by adversaries to steal application access tokens](https://permiso.io/blog/strategies-used-by-adversaries-to-steal-application-access-tokens)
- [CircleCI incident report for January 4, 2023 security incident](https://circleci.com/blog/jan-4-2023-incident-report/)
- [Playbook of the Week: Cloud Token Theft Response](https://www.paloaltonetworks.com/blog/security-operations/playbook-of-the-week-cloud-token-theft-response/)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)

## MITRE ATT&CK Mapping
- [Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)