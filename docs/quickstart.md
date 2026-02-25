# MCP Security Quickstart Guide

## For Security Teams

### 1. Pick Relevant Tactics + Map to Your MCP Tools
- Identify your MCP tools and components in your environment
- Map potential attack vectors using our [Security Glossary](./glossary.md)
- Focus on high-risk areas first

### 2. Apply Mitigations
- Review technique-specific mitigations (e.g., [SAFE-T1102 Prompt Injection](../techniques/prompt-injection.md))
- Implement recommended security controls
- Configure OAuth AS and PoP/DPoP appropriately

### 3. Run Security Checks
- Validate configurations against security checklist
- Monitor for autonomous loop guard triggers
- Regular security assessments

## For Developers

### Getting Started with Secure MCP Development
1. **Understand scope and audience parameters** for your MCP tools
2. **Implement proper context window management**
3. **Follow secure coding practices** outlined in our guidelines
4. **Test security controls** before deployment

### Key Security Checkpoints
- [ ] OAuth AS properly configured
- [ ] Scope limitations implemented  
- [ ] Context window boundaries set
- [ ] Autonomous loop guards active

---
*This quickstart improves adoption and standardizes terminology across security teams and developers.*
