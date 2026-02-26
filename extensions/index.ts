import { ExtensionContext } from "@mariozechner/pi-coding-agent";

export async function activate(ctx: ExtensionContext) {
  ctx.ui.notify("Pi Security Scanner activated.");
  
  // Placeholder for runtime hooks
  ctx.pi.on("tool_call", async (event) => {
    // Logic for runtime shield
    console.log(`Tool call detected: ${event.tool}`);
  });
}
