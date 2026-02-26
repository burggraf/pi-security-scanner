import { ExtensionContext } from "@mariozechner/pi-coding-agent";

const DANGEROUS_PATTERNS = [
  /curl\s+.*http/i,
  /wget\s+.*http/i,
  /git\s+push/i,
  /nc\s+/i,
  />\s*\/etc\//,
  />\s*~\/\.ssh/
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
    console.log(`Tool call detected: ${event.tool}`);
  });
}
