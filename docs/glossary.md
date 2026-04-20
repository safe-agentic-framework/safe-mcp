# MCP Security Glossary

*Standardized terminology following MITRE ATT&CK methodology*

## Core MCP Components

### Host
**Definition**: The system or environment where MCP (Model Context Protocol) components are deployed and executed.
**MCP Context**: Includes the runtime environment, dependencies, and security boundaries for MCP operations.
**Related Techniques**: Host-based attacks, privilege escalation

### Server
**Definition**: The backend component that processes MCP requests and manages tool interactions.
**MCP Context**: Handles authentication, authorization, and tool execution within the MCP framework.
**Related Techniques**: [SAFE-T1102 Prompt Injection](../techniques/), Server-side request forgery

### Tool
**Definition**: Specific capabilities or functions exposed through the MCP interface.
**MCP Context**: Individual tools represent discrete operations (file access, API calls, etc.) available to MCP clients.
**Related Techniques**: Tool misuse, unauthorized tool access

## Authentication & Authorization

### OAuth AS (Authorization Server)
**Definition**: OAuth 2.0 Authorization Server responsible for issuing access tokens for MCP resources.
**MCP Context**: Manages authentication flows and scope-based access control for MCP tools and services.
**Related Techniques**: Token theft, authorization bypass

### PoP/DPoP (Proof of Possession/Demonstration of Proof of Possession)
**Definition**: Cryptographic mechanisms to bind access tokens to specific clients or requests.
**MCP Context**: Prevents token replay attacks and ensures token usage by legitimate MCP clients only.
**Related Techniques**: Token binding, replay attack prevention

### Scope
**Definition**: Access control mechanism defining what resources and operations a client can access.
**MCP Context**: Limits MCP tool access based on granted permissions and use case requirements.
**Related Techniques**: Scope escalation, privilege creep

### Audience
**Definition**: Intended recipient or target system for authentication tokens or MCP requests.
**MCP Context**: Ensures MCP communications are directed to appropriate endpoints and services.
**Related Techniques**: Token misdirection, audience confusion

## Operational Security

### Context Window
**Definition**: The scope of information and history available to MCP operations at any given time.
**MCP Context**: Manages data retention, privacy boundaries, and information flow within MCP sessions.
**Related Techniques**: [SAFE-T1102 Prompt Injection](../techniques/), Context manipulation, information leakage

### Autonomous Loop Guard
**Definition**: Security control preventing infinite or runaway automated operations in MCP systems.
**MCP Context**: Protects against resource exhaustion and uncontrolled MCP tool execution loops.
**Related Techniques**: Resource exhaustion, denial of service, loop exploitation

---
*This glossary standardizes terminology across teams and links to specific security techniques and mitigations.*
