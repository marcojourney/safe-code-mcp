import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { minimatch } from "minimatch";

export type Policy = {
  repoRoot: string;
  allow: string[];
  deny: string[];
  maxReadLines: number;
  auditLog: string;
};

export function loadPolicy(): Policy {
  const raw = fs.readFileSync("policy.yml", "utf8");
  const policy = YAML.parse(raw) as Policy;
  policy.repoRoot = path.resolve(policy.repoRoot);
  policy.auditLog = path.resolve(policy.auditLog);
  return policy;
}

export function safeRelPath(policy: Policy, inputPath: string): string {
  const normalized = inputPath.replaceAll("\\", "/").replace(/^\/+/, "");
  const abs = path.resolve(policy.repoRoot, normalized);

  if (!abs.startsWith(policy.repoRoot + path.sep)) {
    throw new Error("Path escapes repo root");
  }

  const rel = path.relative(policy.repoRoot, abs).replaceAll("\\", "/");

  if (policy.deny.some((p) => minimatch(rel, p, { dot: true }))) {
    throw new Error(`Denied by policy: ${rel}`);
  }

  if (!policy.allow.some((p) => minimatch(rel, p, { dot: true }))) {
    throw new Error(`Not allowed by policy: ${rel}`);
  }

  return rel;
}