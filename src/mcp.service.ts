import fs from "node:fs";
import path from "node:path";
import { Injectable, OnModuleInit } from "@nestjs/common";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { minimatch } from "minimatch";
import { audit } from "./audit.ts";
import { loadPolicy, safeRelPath } from "./policy.ts";
import { redact } from "./redact.ts";
import { StderrLogger } from "./stderr-logger.ts";

@Injectable()
export class McpService implements OnModuleInit {
  // Policy is loaded once at startup so every MCP tool uses the same access rules.
  private readonly policy = loadPolicy();
  private readonly realRepoRoot = fs.realpathSync(this.policy.repoRoot);

  // The MCP server exposes safe repository tools over stdio for Codex or other MCP clients.
  private readonly server = new McpServer({
    name: "safe-code-mcp",
    version: "0.1.0",
  });

  constructor(private readonly logger: StderrLogger) {}

  // Nest lifecycle hook: register all MCP tools, then attach the stdio transport.
  async onModuleInit(): Promise<void> {
    this.logger.log("Registering MCP tools", McpService.name);
    this.registerTools();

    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.log("safe-code-mcp server running on stdio transport", McpService.name);
  }

  // Resolve symlinks and reject reads that escape the configured repository root.
  private assertInsideRepo(abs: string): void {
    const realPath = fs.realpathSync(abs);

    if (
      realPath !== this.realRepoRoot &&
      !realPath.startsWith(this.realRepoRoot + path.sep)
    ) {
      throw new Error("Path escapes repo root");
    }
  }

  // Resolve a repository-relative path without applying allow rules.
  private resolveInsideRepo(inputPath = "."): { rel: string; abs: string } {
    const normalized = inputPath.replaceAll("\\", "/").replace(/^\/+/, "") || ".";
    const abs = path.resolve(this.policy.repoRoot, normalized);

    if (abs !== this.policy.repoRoot && !abs.startsWith(this.policy.repoRoot + path.sep)) {
      throw new Error("Path escapes repo root");
    }

    this.assertInsideRepo(abs);

    return {
      rel: path.relative(this.policy.repoRoot, abs).replaceAll("\\", "/") || ".",
      abs,
    };
  }

  private isDenied(rel: string): boolean {
    if (rel === ".") return false;

    return this.policy.deny.some(
      (pattern) =>
        minimatch(rel, pattern, { dot: true }) ||
        minimatch(`${rel}/__entry__`, pattern, { dot: true })
    );
  }

  private hasAllowedFileUnder(dir: string): boolean {
    for (const item of fs.readdirSync(dir)) {
      const abs = path.join(dir, item);
      const rel = path.relative(this.policy.repoRoot, abs).replaceAll("\\", "/");
      const stat = fs.lstatSync(abs);

      if (stat.isSymbolicLink() || this.isDenied(rel)) continue;

      if (stat.isDirectory() && this.hasAllowedFileUnder(abs)) return true;

      if (stat.isFile()) {
        try {
          safeRelPath(this.policy, rel);
          return true;
        } catch {
          continue;
        }
      }
    }

    return false;
  }

  private readAllowedRange(
    filePath: string,
    startLine: number,
    endLine: number
  ): { rel: string; text: string; endLine: number; redactions: number; totalLines: number } {
    if (endLine < startLine) {
      throw new Error("endLine must be greater than or equal to startLine");
    }

    const rel = safeRelPath(this.policy, filePath);
    const abs = path.join(this.policy.repoRoot, rel);
    this.assertInsideRepo(abs);

    const stat = fs.statSync(abs);
    if (!stat.isFile()) {
      throw new Error(`Not a file: ${rel}`);
    }

    const maxEnd = Math.min(endLine, startLine + this.policy.maxReadLines - 1);
    const lines = fs.readFileSync(abs, "utf8").split(/\r?\n/);
    const selected = lines.slice(startLine - 1, maxEnd).join("\n");
    const result = redact(selected);

    return {
      rel,
      text: result.text,
      endLine: maxEnd,
      redactions: result.redactions,
      totalLines: lines.length,
    };
  }

  // Recursively list files that pass the allow/deny policy and skip symlinks.
  private walk(dir: string): string[] {
    const results: string[] = [];

    for (const item of fs.readdirSync(dir)) {
      const abs = path.join(dir, item);
      const rel = path.relative(this.policy.repoRoot, abs).replaceAll("\\", "/");

      const stat = fs.lstatSync(abs);
      if (stat.isSymbolicLink() || this.isDenied(rel)) continue;

      if (stat.isDirectory()) results.push(...this.walk(abs));
      else {
        try {
          safeRelPath(this.policy, rel);
          results.push(rel);
        } catch {
          continue;
        }
      }
    }

    return results;
  }

  // Register the MCP tools exposed to clients.
  private registerTools(): void {
    // Return all files visible under the configured policy.
    this.server.tool("list_allowed_files", {}, async () => {
      const files = this.walk(this.policy.repoRoot);

      this.audit({
        tool: "list_allowed_files",
        count: files.length,
      });

      return {
        content: [{ type: "text", text: files.join("\n") }],
      };
    });

    // Return the active policy so clients can understand access boundaries.
    this.server.tool("get_policy", {}, async () => {
      const summary = {
        repoRoot: this.policy.repoRoot,
        allow: this.policy.allow,
        deny: this.policy.deny,
        maxReadLines: this.policy.maxReadLines,
        auditLog: this.policy.auditLog,
      };

      this.audit({
        tool: "get_policy",
        allowRules: this.policy.allow.length,
        denyRules: this.policy.deny.length,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
      };
    });

    // List immediate visible children under a directory without returning file contents.
    this.server.tool(
      "list_directory",
      {
        dirPath: z.string().default("."),
      },
      async ({ dirPath }) => {
        const { rel, abs } = this.resolveInsideRepo(dirPath);
        const stat = fs.statSync(abs);

        if (!stat.isDirectory()) {
          throw new Error(`Not a directory: ${rel}`);
        }

        if (this.isDenied(rel)) {
          throw new Error(`Denied by policy: ${rel}`);
        }

        const entries = fs
          .readdirSync(abs)
          .map((name) => {
            const entryAbs = path.join(abs, name);
            const entryRel = path
              .relative(this.policy.repoRoot, entryAbs)
              .replaceAll("\\", "/");
            const entryStat = fs.lstatSync(entryAbs);

            if (entryStat.isSymbolicLink() || this.isDenied(entryRel)) return null;

            if (entryStat.isDirectory()) {
              if (!this.hasAllowedFileUnder(entryAbs)) return null;
              return `${entryRel}/`;
            }

            try {
              safeRelPath(this.policy, entryRel);
              return entryRel;
            } catch {
              return null;
            }
          })
          .filter((entry): entry is string => entry !== null)
          .sort();

        this.audit({
          tool: "list_directory",
          dir: rel,
          count: entries.length,
        });

        return {
          content: [{ type: "text", text: entries.join("\n") }],
        };
      }
    );

    // Return basic metadata for an allowed file without reading its contents.
    this.server.tool(
      "file_info",
      {
        filePath: z.string(),
      },
      async ({ filePath }) => {
        const rel = safeRelPath(this.policy, filePath);
        const abs = path.join(this.policy.repoRoot, rel);
        this.assertInsideRepo(abs);

        const stat = fs.statSync(abs);
        if (!stat.isFile()) {
          throw new Error(`Not a file: ${rel}`);
        }

        const lineCount = fs.readFileSync(abs, "utf8").split(/\r?\n/).length;
        const info = {
          filePath: rel,
          sizeBytes: stat.size,
          lineCount,
          modifiedAt: stat.mtime.toISOString(),
        };

        this.audit({
          tool: "file_info",
          file: rel,
        });

        return {
          content: [{ type: "text", text: JSON.stringify(info, null, 2) }],
        };
      }
    );

    // Read a bounded line range from an allowed file after redacting secrets.
    this.server.tool(
      "read_file",
      {
        filePath: z.string(),
        startLine: z.number().int().min(1).default(1),
        endLine: z.number().int().min(1).default(250),
      },
      async ({ filePath, startLine, endLine }) => {
        const result = this.readAllowedRange(filePath, startLine, endLine);

        this.audit({
          tool: "read_file",
          file: result.rel,
          startLine,
          endLine: result.endLine,
          redactions: result.redactions,
        });

        return {
          content: [{ type: "text", text: result.text }],
        };
      }
    );

    // Read a context window around a target line.
    this.server.tool(
      "read_file_context",
      {
        filePath: z.string(),
        line: z.number().int().min(1),
        contextLines: z.number().int().min(0).max(100).default(20),
      },
      async ({ filePath, line, contextLines }) => {
        const startLine = Math.max(1, line - contextLines);
        const endLine = line + contextLines;
        const result = this.readAllowedRange(filePath, startLine, endLine);

        this.audit({
          tool: "read_file_context",
          file: result.rel,
          line,
          startLine,
          endLine: result.endLine,
          redactions: result.redactions,
        });

        return {
          content: [
            {
              type: "text",
              text:
                `File: ${result.rel}\n` +
                `Lines: ${startLine}-${result.endLine} of ${result.totalLines}\n\n` +
                result.text,
            },
          ],
        };
      }
    );

    // Search allowed files for a literal query and redact sensitive matches.
    this.server.tool(
      "search_code",
      {
        query: z.string().min(2),
      },
      async ({ query }) => {
        const files = this.walk(this.policy.repoRoot);
        this.logger.debug(
          `Searching for "${query}" in ${files.length} files`,
          McpService.name
        );
        const matches: string[] = [];

        for (const rel of files) {
          const abs = path.join(this.policy.repoRoot, rel);
          const lines = fs.readFileSync(abs, "utf8").split(/\r?\n/);

          lines.forEach((line, i) => {
            if (line.includes(query)) {
              const redacted = redact(line).text;
              matches.push(`${rel}:${i + 1}: ${redacted}`);
            }
          });
        }

        this.audit({
          tool: "search_code",
          query,
          matches: matches.length,
        });

        return {
          content: [{ type: "text", text: matches.slice(0, 100).join("\n") }],
        };
      }
    );

    // Accept a patch proposal, scan it for secrets, and return it for manual review.
    this.server.tool(
      "propose_patch",
      {
        filePath: z.string(),
        diff: z.string(),
      },
      async ({ filePath, diff }) => {
        const rel = safeRelPath(this.policy, filePath);
        const scanned = redact(diff);

        this.audit({
          tool: "propose_patch",
          file: rel,
          redactions: scanned.redactions,
        });

        return {
          content: [
            {
              type: "text",
              text:
                `Patch proposal for ${rel}. Review manually before applying:\n\n` +
                scanned.text,
            },
          ],
        };
      }
    );
  }

  // Write an append-only audit event for every tool call.
  private audit(event: Record<string, unknown>): void {
    audit(this.policy.auditLog, event);
  }
}
