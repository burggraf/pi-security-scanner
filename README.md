# Pi Security Scanner

A security extension for `pi-coding-agent` that provides runtime protection and static analysis for your Pi agent environment.

## Features

### 🛡️ Runtime Shield
- **Bash Interceptor**: Detects and blocks dangerous bash commands like `curl`, `wget`, `nc`, and unauthorized system modifications.
- **File Access Monitor**: Protects sensitive files like `.env`, `.ssh/` keys, and `.git/config` from unauthorized writes or edits.
- **`/toggle-shield` Command**: Enables or disables the Runtime Shield. When disabled, no bash commands or file access are intercepted.


### 🔍 Static Scanner
- **/scan-security Command**: Scans all installed Pi extensions (globally and locally) for dangerous patterns such as `eval()`, `child_process.exec()`, and unauthorized network calls.

## Installation

This extension is configured as a pi-package. You can install it by adding it to your Pi configuration:

```bash
pi install npm:pi-security-scanner
```

## How it Works

The scanner leverages Pi's built-in Extension API:
- **`tool_call` Event Hooks**: Intercepts tool execution to provide real-time guardrails.
- **Heuristic Engine**: Uses regex-based analysis to identify suspicious code patterns in extension source files.
- **User Confirmation**: Never blocks silently—always asks for user permission before stopping a suspicious action.
