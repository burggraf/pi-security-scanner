import { ExtensionContext } from "@mariozechner/pi-coding-agent";
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

export async function activate(ctx: ExtensionContext) {
  shieldEnabled = await loadShieldConfig();
  ctx.ui.notify(`Pi Security Scanner activated. Shield: ${shieldEnabled ? "ON" : "OFF"}`);

  ctx.pi.on("tool_call", async (event) => {
    if (!shieldEnabled) return;
    if (event.tool === "bash") {
      const command = (event.args as any).command;
      const isDangerous = DANGEROUS_PATTERNS.some((regex) => regex.test(command));

      if (isDangerous) {
        const confirmed = await ctx.ui.confirm(
          `Suspicious bash command detected: "${command}". Allow execution?`
        );
        if (!confirmed) {
          return { block: true, reason: "Security: User blocked suspicious command." };
        }
      }
    }

    if (event.tool === "write" || event.tool === "edit") {
      const path = (event.args as any).path;
      const isSensitive = SENSITIVE_FILES.some((regex) => regex.test(path));

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

  ctx.pi.registerCommand({
    name: "scan-security",
    description: "Scans installed extensions for security vulnerabilities",
    execute: async () => {
      ctx.ui.notify("Starting security scan...");
      const extensions = await findExtensions();
      ctx.ui.notify(`Found ${extensions.length} extension files to scan.`);

      for (const filePath of extensions) {
        const findings = await analyzeExtension(filePath);
        if (findings.length > 0) {
          ctx.ui.notify(`Warning in ${path.basename(filePath)}:\n` + findings.join("\n"));
        }
      }
    }
  });

  ctx.pi.registerCommand({
    name: "toggle-shield",
    description: "Enable or disable the Runtime Shield",
    execute: async () => {
      shieldEnabled = !shieldEnabled;
      await saveShieldConfig(shieldEnabled);
      ctx.ui.notify(`Runtime Shield is now ${shieldEnabled ? "ENABLED" : "DISABLED"}.`);
    }
  });
}
