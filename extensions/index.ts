import { ExtensionAPI, isToolCallEventType } from "@mariozechner/pi-coding-agent";
import { findExtensions, analyzeExtension } from "../src/scanner.js";
import { loadShieldConfig, saveShieldConfig } from "../src/shield-config.js";
import path from "path";

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
      ctx.ui.notify("Starting security scan...", "info");
      const extensions = await findExtensions();
      ctx.ui.notify(`Found ${extensions.length} extension files to scan.`, "info");

      for (const filePath of extensions) {
        const findings = await analyzeExtension(filePath);
        if (findings.length > 0) {
          ctx.ui.notify(`Warning in ${path.basename(filePath)}:\n` + findings.join("\n"), "warning");
        }
      }
    }
  });

  pi.registerCommand("security-shield", {
    description: "Enable or disable the Runtime Shield",
    handler: async (_args, ctx) => {
      shieldEnabled = !shieldEnabled;
      await saveShieldConfig(shieldEnabled);
      ctx.ui.notify(`Runtime Shield is now ${shieldEnabled ? "ENABLED" : "DISABLED"}.`, shieldEnabled ? "success" : "info");
    }
  });
}
