import path from "path";
import { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { findExtensions, analyzeExtension } from "../src/scanner.js";

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
  ctx.ui.notify("Pi Security Scanner activated.");

  ctx.pi.on("tool_call", async (event) => {
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
}
