import fs from "node:fs";

export function audit(logPath: string, event: Record<string, unknown>) {
  fs.appendFileSync(
    logPath,
    JSON.stringify({ time: new Date().toISOString(), ...event }) + "\n"
  );
}
