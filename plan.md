Plan written to `/Users/markb/dev/pi-security-scanner/plan.md`.

**Summary of the plan — 8 tasks:**

| # | Task | Files |
|---|------|-------|
| 1 | Create `shield-config.json` with `{ "shieldEnabled": true }` | `shield-config.json` (new) |
| 2 | Add commented `.gitignore` entry for config file | `.gitignore` |
| 3 | Create config helper module with `loadShieldConfig` / `saveShieldConfig` | `src/shield-config.ts` (new) |
| 4 | Load config on extension activation, set footer status | `extensions/index.ts` |
| 5 | Add `if (!shieldEnabled) return` guard at top of `tool_call` handler | `extensions/index.ts` |
| 6 | Register `/toggle-shield` command (flips state, persists, notifies) | `extensions/index.ts` |
| 7 | Document the toggle in README (command, config file, warning) | `README.md` |
| 8 | Commit and push all changes | git |

**Key design choices:**
- **Dual persistence**: in-memory boolean for zero-cost runtime checks + `shield-config.json` on disk for cross-session survival
- **Single guard point**: one `if (!shieldEnabled)` at the top of `tool_call` covers both bash interception and file access monitoring
- **Static scanner not gated**: `/scan-security` always works regardless of shield state
- **Footer status**: `🛡️ Shield: ON` / `⚠️ Shield: OFF` for always-visible awareness

**Top risk**: the existing code uses what appears to be a legacy extension API pattern (`ctx.pi.registerCommand({ name, execute })`). If this fails at runtime, all command registrations need refactoring to the modern `pi.registerCommand("name", { handler })` signature.