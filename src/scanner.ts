import fs from "fs/promises";
import path from "path";
import os from "os";

async function getFiles(dir: string): Promise<string[]> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(entries.map(async (entry) => {
      const res = path.resolve(dir, entry.name);
      return entry.isDirectory() ? getFiles(res) : res;
    }));
    return files.flat() as string[];
  } catch (e) {
    return [];
  }
}

export async function findExtensions() {
  const searchPaths = [
    path.join(os.homedir(), ".pi", "agent", "extensions"),
    path.join(process.cwd(), ".pi", "extensions")
  ];
  
  const allFiles = (await Promise.all(searchPaths.map(getFiles))).flat();
  return allFiles.filter(f => f.endsWith(".ts") || f.endsWith(".js"));
}

const MALICIOUS_PATTERNS = [
  /eval\(/,
  /new\s+Function\(/,
  /child_process\.exec\(/,
  /child_process\.spawn\(/,
  /fs\.rm\(/,
  /fs\.rmdir\(/,
  /axios\./,
  /fetch\(/,
  /https\./,
  /http\./,
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
