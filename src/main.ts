import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.ts";
import { StderrLogger } from "./stderr-logger.ts";

const logger = new StderrLogger();

await NestFactory.createApplicationContext(AppModule, {
  logger,
});

logger.log("Nest application context initialized", "Bootstrap");
