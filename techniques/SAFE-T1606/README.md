# SAFE-T1606: Directory Listing via File Tool

## Overview
**Tactic**: Discovery (ATK-TA0007)  
**Technique ID**: SAFE-T1606  
**Severity**: High  
**First Observed**: 2024  
**Last Updated**: 2025-11-26

## Description
Directory Listing via File Tool involves an adversary leveraging legitimate MCP tools (such as `list_directory`, `ls`, or `dir`) to enumerate the file system of the host machine. By listing directories, attackers can discover sensitive files, configuration paths, and system structure, which aids in planning further attacks like file collection or privilege escalation.

This technique exploits valid file system access capabilities granted to an MCP server or tool, repurposing them for reconnaissance.

## Attack Vectors
- **Primary Vector**: Abuse of authorized file system tools (e.g., a "Filesystem" MCP server) to explore unauthorized or sensitive directories.
- **Secondary Vectors**: 
  - Prompt injection to force an AI agent to call directory listing tools on sensitive paths.
  - Compromised or malicious MCP servers that automatically scan the host file system upon connection.

## Technical Details

### Prerequisites
- An MCP tool with directory listing capabilities (e.g., `filesystem/list_directory`) must be available to the LLM.
- The tool must have permissions to read the target directories.

### Attack Flow
1. **Initial Stage**: The attacker (or a malicious prompt) identifies a tool capability for listing files.
2. **Reconnaissance**: The attacker instructs the model to list the contents of sensitive directories (e.g., `/`, `/etc`, `/home/user/.ssh`, `C:\Users\Admin`).
3. **Discovery**: The tool returns the list of files and subdirectories.
4. **Exploitation Stage**: The attacker uses the returned information to identify valuable targets (e.g., `id_rsa`, `.env`, `config.yaml`) for subsequent exfiltration or modification.

### Example Scenario
```json
{
  "tool": "filesystem_list_directory",
  "parameters": {
    "path": "/etc"
  }
}
```
Response:
```json
[
  "passwd",
  "shadow",
  "hosts",
  "ssh/"
]
```

## Impact Assessment
- **Confidentiality**: High - Exposure of file system structure and location of sensitive data.
- **Integrity**: Low - Listing files does not directly alter them, though it facilitates future integrity attacks.
- **Availability**: Low - Standard directory listing is unlikely to cause denial of service.
- **Scope**: Local - Limited to the file system accessible by the MCP host process.

## Detection Methods

### Indicators of Compromise (IoCs)
- Repeated calls to directory listing tools targeting root or system directories.
- Directory listing of paths unrelated to the user's current context or request.
- Enumeration of known sensitive paths (e.g., `.ssh`, `.aws`, `/etc`).

### Behavioral Indicators
- Rapid sequential listing of multiple top-level directories (e.g., `/`, `/etc`, `/var`, `/home`).
- Attempts to list hidden or credential-bearing folders (e.g., `.ssh`, `.aws`, `.git`) outside project scope.
- Directory listing immediately followed by read operations on sensitive files discovered (e.g., `read_file` on `id_rsa`, `.env`).
- Enumeration of system directories from non-privileged or sandboxed contexts.
- Repeated listing attempts after access denied or policy violations.

### Detection Rules

```yaml
title: Suspicious Directory Listing
id: 9e5b2d7a-8c1f-4b5e-9a3d-1f2c3e4d5b6a
status: experimental
description: Detects attempts to list contents of sensitive system directories via MCP tools.
author: Vikranth Kumar Shivaa
date: 2025-11-26
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1606
logsource:
  product: mcp
  service: tool_execution
detection:
  selection:
    tool_name:
      - 'list_directory'
      - 'ls'
      - 'dir'
      - 'filesystem_list_directory'
    parameters.path|contains:
      - '/etc'
      - '/root'
      - 'C:\\Windows'
      - 'C:\\Users\\Administrator'
      - '.ssh'
      - '.aws'
      - '.env'
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1083
  - safe.t1606
falsepositives:
  - Legitimate listings within project workspace or temp directories
  - CI/CD jobs enumerating build artifacts or dependencies
  - IDE extensions scanning project folders for indexing
  - OS/security tools performing routine system scans
fields:
  - timestamp
  - service
  - tool_name
  - parameters.path
  - user_id
```

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-14: Server Allowlisting](../../mitigations/SAFE-M-14/README.md)**: Restrict which MCP servers are allowed to run.
2. **Path Allowlisting**: Configure file system tools to only allow access to specific, safe directories (e.g., project workspace only). Deny access to root (`/`) or system folders by default.
3. **[SAFE-M-9: Sandboxed Testing](../../mitigations/SAFE-M-9/README.md)**: Run MCP servers in isolated containers (e.g., Docker) with limited file system mounts to prevent access to the host's sensitive files.
4. **[SAFE-M-29: Explicit Privilege Boundaries](../../mitigations/SAFE-M-29/README.md)**: Ensure tools operate with the least privilege necessary.

### Detective Controls
1. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Log all tool executions, specifically capturing the `path` arguments for directory listing operations.
2. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Monitor for anomalous patterns of file system traversal (e.g., rapid enumeration of multiple directories).

## Related Techniques
- [SAFE-T1601](../SAFE-T1601/README.md): MCP Server Enumeration - Discovering available servers.
- [SAFE-T1802](../SAFE-T1802/README.md): File Collection - Reading the files discovered via directory listing.

## References
- [MITRE ATT&CK T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## MITRE ATT&CK Mapping
- [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-26 | Initial documentation | Vikranth Kumar Shivaa |

