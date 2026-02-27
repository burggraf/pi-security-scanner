import fs from "fs/promises";
import path from "path";
import os from "os";
import { execSync } from "child_process";

async function getFiles(dir: string, excludeDirs: string[] = ["node_modules", ".git", "dist", "build"]): Promise<string[]> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const files: string[] = [];
    
    for (const entry of entries) {
      const res = path.resolve(dir, entry.name);
      
      if (entry.isDirectory()) {
        
        if (excludeDirs.includes(entry.name)) {
          continue;
        }
        const subFiles = await getFiles(res, excludeDirs);
        files.push(...subFiles);
      } else {
        files.push(res);
      }
    }
    
    return files;
  } catch (e) {
    return [];
  }
}

function getGlobalNpmRoot(): string {
  try {
    return execSync("npm root -g", { encoding: "utf-8" }).trim();
  } catch {
    return path.join(os.homedir(), ".nvm", "versions", "node", process.version, "lib", "node_modules");
  }
}

export async function findExtensions() {
  const npmRoot = getGlobalNpmRoot();
  const allFiles: string[] = [];
  
  
  const piExtensionsPath = path.join(os.homedir(), ".pi", "agent", "extensions");
  try {
    await fs.access(piExtensionsPath);
    const files = await getFiles(piExtensionsPath);
    allFiles.push(...files.filter(f => f.endsWith(".ts") || f.endsWith(".js")));
  } catch { /* directory doesn't exist */ }
  
  
  const localExtensionsPath = path.join(process.cwd(), ".pi", "extensions");
  try {
    await fs.access(localExtensionsPath);
    const files = await getFiles(localExtensionsPath);
    allFiles.push(...files.filter(f => f.endsWith(".ts") || f.endsWith(".js")));
  } catch { /* directory doesn't exist */ }
  
  
  const skillsPath = path.join(os.homedir(), ".agents", "skills");
  try {
    await fs.access(skillsPath);
    const files = await getFiles(skillsPath);
    allFiles.push(...files.filter(f => f.endsWith(".ts") || f.endsWith(".js")));
  } catch { /* directory doesn't exist */ }
  
  
  try {
    await fs.access(npmRoot);
    const entries = await fs.readdir(npmRoot, { withFileTypes: true });
    
    for (const entry of entries) {
      const isPiPackage = entry.name.startsWith("pi-");
      const isScopedPiPackage = entry.name.startsWith("@") && !entry.isFile();
      
      if (isPiPackage) {
        const packagePath = path.join(npmRoot, entry.name);
        const files = await getFiles(packagePath);
        allFiles.push(...files.filter(f => f.endsWith(".ts") || f.endsWith(".js")));
      } else if (isScopedPiPackage) {
        const scopePath = path.join(npmRoot, entry.name);
        try {
          const scopeEntries = await fs.readdir(scopePath, { withFileTypes: true });
          for (const scopeEntry of scopeEntries) {
            if (scopeEntry.name.startsWith("pi-")) {
              const packagePath = path.join(scopePath, scopeEntry.name);
              const files = await getFiles(packagePath);
              allFiles.push(...files.filter(f => f.endsWith(".ts") || f.endsWith(".js")));
            }
          }
        } catch { /* ignore scope read errors */ }
      }
    }
  } catch { /* npm root doesn't exist */ }
  
  return allFiles;
}

/**
 * Security patterns that indicate potentially malicious code.
 * 
 * HIGH SEVERITY - Code Execution:
 * - eval() - Executes arbitrary JavaScript code
 * - new Function() - Creates functions from strings, similar to eval
 * - vm.runInContext / vm.runInNewContext - Executes code in VM contexts
 * 
 * MEDIUM SEVERITY - Shell Execution:
 * - child_process.exec() with dynamic commands - Can execute shell commands
 * - child_process.execSync() with dynamic commands
 * 
 * LOW SEVERITY - File System Operations:
 * - fs.rm() with recursive option - Can delete entire directories
 * - fs.rmdir() with recursive option
 * 
 * NOTE: We intentionally do NOT flag:
 * - fetch() / axios / https / http - Network requests are common and legitimate
 * - child_process.spawn with static args - Often used for legitimate CLI tools
 * - fs.writeFile / fs.readFile - Common file operations
 */
export const SECURITY_PATTERNS = {
  HIGH: [
    { pattern: /eval\s*\(/, description: "eval() - Arbitrary code execution" },
    { pattern: /new\s+Function\s*\(/, description: "new Function() - Dynamic code creation" },
    { pattern: /vm\.runIn(New)?Context\s*\(/, description: "vm.runInContext() - VM code execution" },
  ],
  MEDIUM: [
    { pattern: /child_process\.exec\s*\([^)]*\$/, description: "exec() with potential variable injection" },
    { pattern: /child_process\.execSync\s*\([^)]*\$/, description: "execSync() with potential variable injection" },
  ],
  LOW: [
    { pattern: /fs\.rm\s*\([^)]*recursive\s*:\s*true/, description: "fs.rm() with recursive deletion" },
    { pattern: /fs\.rmdir\s*\([^)]*recursive\s*:\s*true/, description: "fs.rmdir() with recursive deletion" },
  ],
};

/**
 * Prompt injection patterns that may indicate an extension is attempting to
 * manipulate the LLM's behavior or extract sensitive information.
 * 
 * These patterns look for strings that could be used to:
 * - Override system instructions
 * - Extract system prompts or configuration
 * - Bypass safety guidelines
 * - Inject malicious instructions into context
 */
export const PROMPT_INJECTION_PATTERNS = {
  CRITICAL: [
    // Direct instruction overrides
    { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, description: "Instruction override attempt" },
    { pattern: /disregard\s+(your\s+)?(system\s+)?(prompt|instructions)/i, description: "System prompt disregard attempt" },
    { pattern: /forget\s+(everything|all|your)\s+(I\s+said|previous|system|instructions)/i, description: "Memory wipe attempt" },
    { pattern: /override\s+your\s+(safety\s+)?(rules|guidelines|restrictions)/i, description: "Safety override attempt" },
    { pattern: /bypass\s+(your\s+)?(safety|security|restrictions)/i, description: "Security bypass attempt" },
  ],
  HIGH: [
    // System prompt exfiltration
    { pattern: /reveal\s+(the\s+)?system\s+prompt/i, description: "System prompt exfiltration attempt" },
    { pattern: /show\s+(me\s+)?(your\s+)?(system\s+)?prompt/i, description: "Prompt disclosure attempt" },
    { pattern: /print\s+(the\s+)?(system\s+)?prompt/i, description: "Prompt extraction attempt" },
    { pattern: /what\s+is\s+your\s+(system\s+)?prompt/i, description: "Prompt inquiry" },
    { pattern: /reveal\s+(your\s+)?hidden\s+(instructions|prompt|configuration)/i, description: "Hidden config extraction" },
    { pattern: /show\s+internal\s+configuration/i, description: "Internal config disclosure" },
  ],
  MEDIUM: [
    // Role/persona manipulation
    { pattern: /act\s+as\s+(DAN|do\s+anything\s+now)/i, description: "DAN jailbreak attempt" },
    { pattern: /act\s+as\s+(a\s+)?(system\s+)?admin(istrator)?/i, description: "Admin role assumption" },
    { pattern: /pretend\s+you('re|\s+are)\s+an?\s+admin/i, description: "Admin impersonation" },
    { pattern: /for\s+the\s+rest\s+of\s+this\s+conversation,\s+you\s+are/i, description: "Persistent role override" },
    { pattern: /developer\s+mode.*ignore/i, description: "Developer mode jailbreak" },
    { pattern: /jailbreak/i, description: "Jailbreak keyword" },
    { pattern: /uncensored|no\s+filters/i, description: "Filter bypass attempt" },
  ],
  LOW: [
    // Sensitive data probing
    { pattern: /(admin|root)\s+password/i, description: "Password probing" },
    { pattern: /api[_-]?key/i, description: "API key probing" },
    { pattern: /master\s+key/i, description: "Master key probing" },
    { pattern: /print\s+all\s+(passwords|secrets|credentials)/i, description: "Credential dump attempt" },
    { pattern: /dump\s+(all\s+)?(secrets|credentials|config)/i, description: "Data exfiltration attempt" },
  ],
};

export interface SecurityFinding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  line?: number;
  category: "CODE_EXECUTION" | "PROMPT_INJECTION";
}

export async function analyzeExtension(filePath: string): Promise<SecurityFinding[]> {
  const content = await fs.readFile(filePath, "utf-8");
  const lines = content.split("\n");
  const findings: SecurityFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check code execution patterns (HIGH severity)
    for (const { pattern, description } of SECURITY_PATTERNS.HIGH) {
      if (pattern.test(line)) {
        findings.push({ severity: "HIGH", description, line: lineNum, category: "CODE_EXECUTION" });
      }
    }

    // Check code execution patterns (MEDIUM severity)
    for (const { pattern, description } of SECURITY_PATTERNS.MEDIUM) {
      if (pattern.test(line)) {
        findings.push({ severity: "MEDIUM", description, line: lineNum, category: "CODE_EXECUTION" });
      }
    }

    // Check code execution patterns (LOW severity)
    for (const { pattern, description } of SECURITY_PATTERNS.LOW) {
      if (pattern.test(line)) {
        findings.push({ severity: "LOW", description, line: lineNum, category: "CODE_EXECUTION" });
      }
    }

    // Check prompt injection patterns (CRITICAL severity)
    for (const { pattern, description } of PROMPT_INJECTION_PATTERNS.CRITICAL) {
      if (pattern.test(line)) {
        findings.push({ severity: "CRITICAL", description, line: lineNum, category: "PROMPT_INJECTION" });
      }
    }

    // Check prompt injection patterns (HIGH severity)
    for (const { pattern, description } of PROMPT_INJECTION_PATTERNS.HIGH) {
      if (pattern.test(line)) {
        findings.push({ severity: "HIGH", description, line: lineNum, category: "PROMPT_INJECTION" });
      }
    }

    // Check prompt injection patterns (MEDIUM severity)
    for (const { pattern, description } of PROMPT_INJECTION_PATTERNS.MEDIUM) {
      if (pattern.test(line)) {
        findings.push({ severity: "MEDIUM", description, line: lineNum, category: "PROMPT_INJECTION" });
      }
    }

    // Check prompt injection patterns (LOW severity)
    for (const { pattern, description } of PROMPT_INJECTION_PATTERNS.LOW) {
      if (pattern.test(line)) {
        findings.push({ severity: "LOW", description, line: lineNum, category: "PROMPT_INJECTION" });
      }
    }
  }

  return findings;
}
