# 🛡️ MCP-SHIELD

> **Zero-dependency security auditor for local MCP servers, `SKILL.md` files, and AI coding agent configs.**

[![Verify Scanner](https://github.com/Ayubkhokhar/mcp-shield/actions/workflows/test.yml/badge.svg)](https://github.com/Ayubkhokhar/mcp-shield/actions/workflows/test.yml)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](package.json)

---

Developers install third-party Model Context Protocol (MCP) servers and agent rules (`CLAUDE.md`, `.cursorrules`, `SKILL.md`) every day. A single compromised skill or unpinned `npx` MCP server can silently exfiltrate `.env` secrets or inject hidden instructions into your coding agent.

`mcp-shield` audits your local workspace and global IDE configs in under 50ms—completely offline, with zero dependencies.

---

## ⚡ QUICK START

Run directly inside any project directory:

```bash
npx mcp-shield
```

Or scan a specific target directory:

```bash
npx mcp-shield ./path/to/project
```

---

## 🔍 WHAT IT DETECTS

### 1. MCP Configuration Vulnerabilities
Scans `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `cline_mcp_settings.json`, and Claude Desktop configs for:
- **Unpinned `npx` commands**: Packages running without pinned versions (`@latest` or omitted versions).
- **Auto-execution (`-y` / `--yes`)**: Auto-approving remote package downloads without version verification.
- **Shell injections**: Commands containing pipes (`|`), chaining (`&&`, `;`), command substitution (`$()`, backticks), or remote URLs.
- **Hardcoded secrets**: Exposed OpenAI, Anthropic, GitHub PAT, AWS, Slack, and Stripe keys in environment variables.

### 2. Malicious AI Agent Instructions
Recursively audits `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, and `.windsurfrules` for:
- **Prompt Injection & Overrides**: Phrases designed to bypass guardrails (e.g. `ignore previous instructions`, `reveal your system prompt`).
- **Data Exfiltration**: Covert exfiltration payloads (`curl -d`, `wget --post-data`, and tunneling services like `webhook.site`, `ngrok`, `requestbin`).
- **Obfuscation**: `eval()`, `exec()`, and `base64 -d` commands.
- **Sensitive System File Access**: Attempts to access `/etc/passwd`, `~/.ssh`, or `.aws/credentials`.
- **Steganographic Injections**: Hidden HTML comments (`<!-- ignore ... -->`) and invisible zero-width Unicode characters (`\u200B`–`\u200D`, `\uFEFF`) used to hide prompts from human inspection.

---

## 📊 TRUST SCORE & EXIT CODES

`mcp-shield` scores your setup from `0` to `100`:
- **CRITICAL**: -35 points (exits with code `1`)
- **HIGH**: -20 points
- **WARN**: -10 points

If any **CRITICAL** vulnerability is detected, `mcp-shield` exits with code `1`, making it ideal for CI/CD gates and pre-commit hooks.

---

## 🚀 CI / CD INTEGRATION

Add `mcp-shield` to your GitHub Actions workflow:

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run MCP Shield
        run: npx mcp-shield .
```

---

## 📄 LICENSE

[MIT](package.json) © [Ayub Khokhar](https://github.com/Ayubkhokhar)
