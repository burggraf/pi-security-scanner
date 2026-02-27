import { ExtensionAPI, isToolCallEventType } from "@mariozechner/pi-coding-agent";
import { findExtensions, analyzeExtension } from "../src/scanner.js";
import { loadShieldConfig, saveShieldConfig } from "../src/shield-config.js";
import path from "path";
import os from "os";

let shieldEnabled = true;

const DANGEROUS_PATTERNS = [
  /curl\s+.*http/i,
  /wget\s+.*http/i,
  /git\s+push/i,
  /nc\s+/i,
  />\s*\/etc\//,
  />\s*~\/\.ssh/
];

const SENSITIVE_FILES = [
  /\.env$/,
  /\.ssh\//,
  /\.git\/config$/,
  /package-lock\.json$/
];

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async (_event, ctx) => {
    shieldEnabled = await loadShieldConfig();
    ctx.ui.notify(`Pi Security Scanner activated. Shield: ${shieldEnabled ? "ON" : "OFF"}`, "info");
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!shieldEnabled) return;

    if (isToolCallEventType("bash", event)) {
      const command = event.input.command;
      const isDangerous = DANGEROUS_PATTERNS.some((regex) => regex.test(command));

      if (isDangerous) {
        const confirmed = await ctx.ui.confirm(
          "Security Warning",
          `Suspicious bash command detected: "${command}". Allow execution?`
        );
        if (!confirmed) {
          return { block: true, reason: "Security: User blocked suspicious command." };
        }
      }
    }

    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      const filePath = event.input.path;
      const isSensitive = SENSITIVE_FILES.some((regex) => regex.test(filePath));

      if (isSensitive) {
        const confirmed = await ctx.ui.confirm(
          "Security Warning",
          `Attempting to modify sensitive file: "${filePath}". Allow?`
        );
        if (!confirmed) {
          return { block: true, reason: "Security: User blocked access to sensitive file." };
        }
      }
    }
  });

  pi.registerCommand("security-scan", {
    description: "Scans installed extensions for security vulnerabilities",
    handler: async (_args, ctx) => {
      ctx.ui.notify("🔍 Starting security scan...", "info");
      const extensions = await findExtensions();
      ctx.ui.notify(`Found ${extensions.length} extension files to scan.`, "info");

      let totalWarnings = 0;
      const highWarnings: string[] = [];
      const mediumWarnings: string[] = [];
      const lowWarnings: string[] = [];

      for (const filePath of extensions) {
        const findings = await analyzeExtension(filePath);
        if (findings.length > 0) {
          totalWarnings += findings.length;
          const relativePath = filePath.replace(os.homedir(), "~");
          
          for (const finding of findings) {
            const lineInfo = finding.line ? ` (line ${finding.line})` : "";
            const message = `⚠️  ${relativePath}${lineInfo}:\n   ${finding.description}`;
            
            if (finding.severity === "HIGH") highWarnings.push(message);
            else if (finding.severity === "MEDIUM") mediumWarnings.push(message);
            else lowWarnings.push(message);
          }
        }
      }

      const allWarnings = [...highWarnings, ...mediumWarnings, ...lowWarnings];

      if (allWarnings.length > 0) {
        let summary = "\n🚨 Security Scan Complete\n";
        summary += `   ${totalWarnings} warning(s) found in ${allWarnings.length} file(s)\n`;
        if (highWarnings.length > 0) summary += `   • ${highWarnings.length} HIGH severity\n`;
        if (mediumWarnings.length > 0) summary += `   • ${mediumWarnings.length} MEDIUM severity\n`;
        if (lowWarnings.length > 0) summary += `   • ${lowWarnings.length} LOW severity\n`;
        summary += `\n${allWarnings.join("\n\n")}`;
        ctx.ui.notify(summary, "warning");
      } else {
        ctx.ui.notify(`✅ Security Scan Complete: No issues found in ${extensions.length} extension files.`, "info");
      }
    }
  });

  pi.registerCommand("security-shield", {
    description: "Enable or disable the Runtime Shield",
    handler: async (_args, ctx) => {
      shieldEnabled = !shieldEnabled;
      await saveShieldConfig(shieldEnabled);
      ctx.ui.notify(`Runtime Shield is now ${shieldEnabled ? "ENABLED" : "DISABLED"}.`, "info");
    }
  });
}
