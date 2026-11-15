#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

// ANSI Color Helpers (Zero dependencies)
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

const targetDir = path.resolve(process.argv[2] || process.cwd());

const CONFIG_TARGETS = [
  '.cursor/mcp.json',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.vscode/mcp.json',
  'cline_mcp_settings.json',
  'mcp.json',
];

const GLOBAL_TARGETS = [
  path.join(os.homedir(), '.cursor', 'mcp.json'),
  path.join(os.homedir(), '.claude', 'settings.json'),
  path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'),
];

const INJECTION_PATTERNS = [
  { regex: /ignore (all )?(previous|prior) instructions/i, label: 'Prompt Injection Override' },
  { regex: /system prompt|reveal your instructions/i, label: 'System Prompt Extraction' },
  { regex: /curl\s+.*(-d|--data|--upload-file|\|)/i, label: 'Suspicious Data Exfiltration via curl' },
  { regex: /wget\s+.*--post-(data|file)/i, label: 'Suspicious Data Exfiltration via wget' },
  { regex: /base64\s+-d|eval\s*\(|exec\s*\(/i, label: 'Obfuscated Payload Execution' },
  { regex: /\/etc\/passwd|~\/\.ssh|\.aws\/credentials/i, label: 'Sensitive System File Access' },
  { regex: /webhook\.site|requestbin|ngrok\.io|pipedream/i, label: 'Known Exfiltration Tunnel Domain' },
];

const SECRET_PATTERNS = [
  { regex: /sk-[a-zA-Z0-9]{20,}/, label: 'OpenAI / Anthropic API Key' },
  { regex: /ghp_[a-zA-Z0-9]{36}/, label: 'GitHub Personal Access Token' },
  { regex: /AKIA[0-9A-Z]{16}/, label: 'AWS Access Key ID' },
  { regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/, label: 'Slack Token' },
  { regex: /sk_live_[0-9a-zA-Z]{24,}/, label: 'Stripe Live Secret Key' },
];

const findings = [];
let filesScanned = 0;

function addFinding(severity, file, title, detail) {
  findings.push({ severity, file, title, detail });
}

function scanMcpConfig(filePath) {
  if (!fs.existsSync(filePath)) return;
  filesScanned++;
  const relPath = path.relative(targetDir, filePath) || filePath;

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const json = JSON.parse(raw);
    const servers = json.mcpServers || json.servers || {};

    for (const [name, cfg] of Object.entries(servers)) {
      const cmd = `${cfg.command \vert{}\vert{} ''}${(cfg.args || []).join(' ')}`.trim();

      // Check unpinned npx execution
      if (cmd.includes('npx') && !cmd.includes('@') && !cmd.includes('-y')) {
        addFinding('WARN', relPath, `Unpinned npx package in "${name}"`, `Command: ${cmd}`);
      }
      if (cmd.includes('npx -y') || cmd.includes('npx --yes')) {
        addFinding('WARN', relPath, `Auto-executing remote package in "${name}"`, `Uses -y flag without version lock: ${cmd}`);
      }

      // Check shell piping or remote scripts
      if (/(\||;|&&|\$\(|`)/.test(cmd) || /https?:\/\//.test(cmd)) {
        addFinding('HIGH', relPath, `Shell injection or remote URL in MCP command "${name}"`, cmd);
      }

      // Check hardcoded secrets in env block
      if (cfg.env && typeof cfg.env === 'object') {
        for (const [envKey, envVal] of Object.entries(cfg.env)) {
          const valStr = String(envVal);
          for (const pattern of SECRET_PATTERNS) {
            if (pattern.regex.test(valStr)) {
              addFinding('CRITICAL', relPath, `Hardcoded ${pattern.label} in "${name}" (${envKey})`, 'Move secrets to a gitignored .env file.');
            }
          }
        }
      }
    }
  } catch (err) {
    addFinding('WARN', relPath, 'Malformed JSON in MCP Config', err.message);
  }
}

function walkSkillsAndRules(dir, depth = 0) {
  if (depth > 4 || !fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (['node_modules', '.git', 'vendor', 'dist', 'build'].includes(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      walkSkillsAndRules(fullPath, depth + 1);
    } else if (
      entry.isFile() &&
      /^(SKILL\.md|CLAUDE\.md|AGENTS\.md|\.cursorrules|\.windsurfrules)$/i.test(entry.name)
    ) {
      filesScanned++;
      const relPath = path.relative(targetDir, fullPath);
      const content = fs.readFileSync(fullPath, 'utf8');

      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(content)) {
          addFinding('CRITICAL', relPath, pattern.label, `Matched pattern: ${pattern.regex}`);
        }
      }

      // Detect hidden HTML comments or zero-width characters used to hide instructions
      if (/<!--[\s\S]*?(ignore|curl|secret|env|password)[\s\S]*?-->/i.test(content)) {
        addFinding('CRITICAL', relPath, 'Hidden Malicious HTML Comment', 'Suspicious instructions concealed inside Markdown comment.');
      }
      if (/[\u200B-\u200D\uFEFF]/.test(content)) {
        addFinding('HIGH', relPath, 'Zero-Width Unicode Characters Detected', 'Invisible characters are often used to obfuscate prompt injections.');
      }
    }
  }
}

// Banner
console.log(`\n${C.cyan}${C.bold}🛡️  MCP-SHIELD v1.0.0${C.reset} ${C.dim}— AI Agent & MCP Security Auditor${C.reset}`);
console.log(`${C.dim}Target: ${targetDir}${C.reset}\n`);

// Execute Scans
CONFIG_TARGETS.forEach((rel) => scanMcpConfig(path.join(targetDir, rel)));
GLOBAL_TARGETS.forEach((abs) => scanMcpConfig(abs));
walkSkillsAndRules(targetDir);

// Calculate Score
let score = 100;
for (const f of findings) {
  if (f.severity === 'CRITICAL') score -= 35;
  if (f.severity === 'HIGH') score -= 20;
  if (f.severity === 'WARN') score -= 10;
}
score = Math.max(0, score);

// Print Results
if (findings.length === 0) {
  console.log(`${C.green}${C.bold}✔ No security threats or exposed secrets detected!${C.reset}`);
} else {
  for (const f of findings) {
    const badge =
      f.severity === 'CRITICAL'
        ? `${C.red}${C.bold}[CRITICAL]${C.reset}`
        : f.severity === 'HIGH'
        ? `${C.magenta}${C.bold}[HIGH]${C.reset}`
        : `${C.yellow}${C.bold}[WARN]${C.reset}`;

    console.log(`${badge} ${C.bold}${f.title}${C.reset}`);
    console.log(`   ${C.dim}File:${C.reset}   ${f.file}`);
    console.log(`   ${C.dim}Detail:${C.reset} ${f.detail}\n`);
  }
}

const scoreColor = score >= 80 ? C.green : score >= 50 ? C.yellow : C.red;
console.log(`${C.dim}────────────────────────────────────────────────────${C.reset}`);
console.log(`Files Audited: ${C.bold}${filesScanned}${C.reset}  |  Issues Found: ${C.bold}${findings.length}${C.reset}  |  Trust Score: ${scoreColor}${C.bold}${score}/100${C.reset}`);
console.log(`${C.dim}────────────────────────────────────────────────────${C.reset}\n`);

process.exit(findings.some((f) => f.severity === 'CRITICAL') ? 1 : 0);