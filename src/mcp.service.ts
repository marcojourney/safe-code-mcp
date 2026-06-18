import fs from "node:fs";
import path from "node:path";
import { Injectable, OnModuleInit } from "@nestjs/common";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
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

  // Recursively list files that pass the allow/deny policy and skip symlinks.
  private walk(dir: string): string[] {
    const results: string[] = [];

    for (const item of fs.readdirSync(dir)) {
      const abs = path.join(dir, item);
      const rel = path.relative(this.policy.repoRoot, abs).replaceAll("\\", "/");

      try {
        safeRelPath(this.policy, rel);
      } catch {
        continue;
      }

      const stat = fs.lstatSync(abs);
      if (stat.isSymbolicLink()) continue;

      if (stat.isDirectory()) results.push(...this.walk(abs));
      else results.push(rel);
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

    this.server.tool(
      // Read a bounded line range from an allowed file after redacting secrets.
      "read_file",
      {
        filePath: z.string(),
        startLine: z.number().int().min(1).default(1),
        endLine: z.number().int().min(1).default(250),
      },
      async ({ filePath, startLine, endLine }) => {
        const rel = safeRelPath(this.policy, filePath);
        const abs = path.join(this.policy.repoRoot, rel);
        this.assertInsideRepo(abs);

        const maxEnd = Math.min(endLine, startLine + this.policy.maxReadLines - 1);
        const lines = fs.readFileSync(abs, "utf8").split(/\r?\n/);
        const selected = lines.slice(startLine - 1, maxEnd).join("\n");

        const result = redact(selected);

        this.audit({
          tool: "read_file",
          file: rel,
          startLine,
          endLine: maxEnd,
          redactions: result.redactions,
        });

        return {
          content: [{ type: "text", text: result.text }],
        };
      }
    );

    this.server.tool(
      // Search allowed files for a literal query and redact sensitive matches.
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

    this.server.tool(
      // Accept a patch proposal, scan it for secrets, and return it for manual review.
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
