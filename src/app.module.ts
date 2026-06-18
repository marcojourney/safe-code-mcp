import { Module } from "@nestjs/common";
import { McpService } from "./mcp.service.ts";
import { StderrLogger } from "./stderr-logger.ts";

@Module({
  providers: [StderrLogger, McpService],
})
export class AppModule {}
