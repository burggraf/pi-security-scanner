# Pi Security Scanner Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Build a Pi extension that provides static scanning of installed extensions and runtime protection against prompt injection and malicious tool usage.

**Architecture:** A multi-layered security extension consisting of a Static Analysis module (AST-based scanning of extensions) and a Runtime Shield (interceptor for tool calls and context hooks).

**Tech Stack:** TypeScript, `@mariozechner/pi-coding-agent` (Extension API), `acorn` (AST parsing), `zod` or `TypeBox` (schema validation).

---

### Task 1: Repository Setup and Initial Configuration

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `.gitignore`

**Step 1: Create package.json**
Create `package.json` with the following content:
```json
{
  "name": "pi-security-scanner",
  "version": "0.1.0",
  "description": "Security scanner and runtime protection for Pi Coding Agent",
  "main": "extensions/index.ts",
  "repository": {
    "type": "git",
    "url": "https://github.com/burggraf/pi-security-scanner.git"
  },
  "keywords": [
    "pi-package",
    "security",
    "scanner"
  ],
  "pi": {
    "extensions": [
      "extensions/index.ts"
    ]
  },
  "devDependencies": {
    "@mariozechner/pi-coding-agent": "*",
    "@sinclair/typebox": "*",
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "vitest": "^1.0.0"
  }
}
```

**Step 2: Create tsconfig.json**
Create `tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true,
    "skipLibCheck": true,
    "outDir": "dist"
  },
  "include": ["extensions/**/*", "src/**/*"]
}
```

**Step 3: Create .gitignore**
Create `.gitignore`:
```text
node_modules
dist
.pi
*.log
```

**Step 4: Initial Commit**
Run: `git add . && git commit -m "chore: initial project setup"`

---

### Task 2: Basic Extension Entry Point

**Files:**
- Create: `extensions/index.ts`

**Step 1: Write initial extension code**
Create `extensions/index.ts` that exports the required `activate` function:
```typescript
import { ExtensionContext } from "@mariozechner/pi-coding-agent";

export async function activate(ctx: ExtensionContext) {
  ctx.ui.notify("Pi Security Scanner activated.");
  
  // Placeholder for runtime hooks
  ctx.pi.on("tool_call", async (event) => {
    // Logic for runtime shield
    console.log(`Tool call detected: ${event.tool}`);
  });
}
```

**Step 2: Commit**
Run: `git add extensions/index.ts && git commit -m "feat: initial extension entry point"`

---

### Task 3: Runtime Shield - Bash Interceptor

**Files:**
- Modify: `extensions/index.ts`

**Step 1: Implement bash tool interception**
Update the `tool_call` listener to detect dangerous patterns in the `bash` tool:
```typescript
const DANGEROUS_PATTERNS = [
  /curl\s+.*http/i,
  /wget\s+.*http/i,
  /git\s+push/i,
  /nc\s+/i,
  />\s*\/etc\//,
  />\s*~\/\.ssh/
];

ctx.pi.on("tool_call", async (event) => {
  if (event.tool === "bash") {
    const command = (event.args as any).command;
    const isDangerous = DANGEROUS_PATTERNS.some(regex => regex.test(command));
    
    if (isDangerous) {
      const confirmed = await ctx.ui.confirm(
        `Suspicious bash command detected: "${command}". Allow execution?`
      );
      if (!confirmed) {
        return { block: true, reason: "Security: User blocked suspicious command." };
      }
    }
  }
});
```

**Step 2: Commit**
Run: `git add extensions/index.ts && git commit -m "feat: add bash tool runtime protection"`

---

### Task 4: Runtime Shield - File Access Monitor

**Files:**
- Modify: `extensions/index.ts`

**Step 1: Intercept write and edit tools**
Add checks for sensitive file paths in `write` and `edit` tools:
```typescript
const SENSITIVE_FILES = [
  /\.env$/,
  /\.ssh\//,
  /\.git\/config$/,
  /package-lock\.json$/
];

ctx.pi.on("tool_call", async (event) => {
  if (event.tool === "write" || event.tool === "edit") {
    const path = (event.args as any).path;
    const isSensitive = SENSITIVE_FILES.some(regex => regex.test(path));
    
    if (isSensitive) {
      const confirmed = await ctx.ui.confirm(
        `Attempting to modify sensitive file: "${path}". Allow?`
      );
      if (!confirmed) {
        return { block: true, reason: "Security: User blocked access to sensitive file." };
      }
    }
  }
});
```

**Step 2: Commit**
Run: `git add extensions/index.ts && git commit -m "feat: add file access monitor"`

---

### Task 5: Static Scanner - Extension Discovery

**Files:**
- Create: `src/scanner.ts`
- Modify: `extensions/index.ts`

**Step 1: Implement extension discovery logic**
In `src/scanner.ts`, write logic to find Pi extensions:
```typescript
import fs from "fs/promises";
import path from "path";
import os from "os";

export async function findExtensions() {
  const paths = [
    path.join(os.homedir(), ".pi", "agent", "extensions"),
    path.join(process.cwd(), ".pi", "extensions")
  ];
  // Logic to read directories and find .ts/.js files
  // ...
}
```

**Step 2: Register /scan-security command**
Update `extensions/index.ts` to register the command:
```typescript
ctx.pi.registerCommand({
  name: "scan-security",
  description: "Scans installed extensions for security vulnerabilities",
  execute: async () => {
    ctx.ui.notify("Starting security scan...");
    // Call findExtensions and analyze them
  }
});
```

**Step 3: Commit**
Run: `git add src/scanner.ts extensions/index.ts && git commit -m "feat: add extension discovery and /scan-security command"`

---

### Task 6: Static Scanner - Heuristic Analysis

**Files:**
- Modify: `src/scanner.ts`

**Step 1: Implement simple heuristic analysis**
Add regex or AST checks for dangerous functions in extension code:
```typescript
const MALICIOUS_PATTERNS = [
  /eval\(/,
  /new\s+Function\(/,
  /child_process\.exec\(/
];

export async function analyzeExtension(filePath: string) {
  const content = await fs.readFile(filePath, "utf-8");
  const findings = [];
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(content)) {
      findings.push(`Dangerous pattern found: ${pattern}`);
    }
  }
  return findings;
}
```

**Step 2: Commit**
Run: `git add src/scanner.ts && git commit -m "feat: add basic heuristic analysis for extensions"`

---

### Task 7: Documentation and README

**Files:**
- Create: `README.md`

**Step 1: Create README.md**
Document how to install and use the extension, and the threats it protects against.

**Step 2: Commit**
Run: `git add README.md && git commit -m "docs: add README"`

---

### Task 8: Public Repository Creation

**Step 1: Create GitHub Repo**
Run: `gh repo create pi-security-scanner --public --source=. --remote=origin --push`
