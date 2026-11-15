# 🛡️ mcp-shield

**Zero-dependency security auditor for local MCP servers, `SKILL.md` files, and AI coding agent configs.**

Developers install third-party Model Context Protocol (MCP) servers and agent rules (`CLAUDE.md`, `.cursorrules`, `SKILL.md`) every day. A single compromised skill or unpinned `npx` MCP server can silently exfiltrate `.env` secrets or inject hidden instructions into your coding agent.

`mcp-shield` audits your local workspace and global IDE configs in under 50ms—completely offline, with zero dependencies.

---

## ⚡ Quick Start

Run directly inside any project directory:

```bash
npx mcp-shield