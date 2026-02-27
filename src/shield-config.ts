import fs from "fs/promises";
import path from "path";

const CONFIG_PATH = path.join(process.cwd(), ".pi-security-shield.json");

export async function loadShieldConfig(): Promise<boolean> {
  try {
    const data = await fs.readFile(CONFIG_PATH, "utf-8");
    const config = JSON.parse(data);
    return config.shieldEnabled !== false; // Default to true
  } catch {
    return true;
  }
}

export async function saveShieldConfig(enabled: boolean) {
  await fs.writeFile(CONFIG_PATH, JSON.stringify({ shieldEnabled: enabled }, null, 2));
}
