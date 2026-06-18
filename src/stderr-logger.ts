import { Injectable, LoggerService } from "@nestjs/common";

type LogLevel = "log" | "error" | "warn" | "debug" | "verbose";

@Injectable()
export class StderrLogger implements LoggerService {
  log(message: unknown, context?: string): void {
    this.write("log", message, context);
  }

  error(message: unknown, trace?: string, context?: string): void {
    this.write("error", message, context);
    if (trace) process.stderr.write(`${trace}\n`);
  }

  warn(message: unknown, context?: string): void {
    this.write("warn", message, context);
  }

  debug(message: unknown, context?: string): void {
    this.write("debug", message, context);
  }

  verbose(message: unknown, context?: string): void {
    this.write("verbose", message, context);
  }

  private write(level: LogLevel, message: unknown, context?: string): void {
    const time = new Date().toISOString();
    const label = level.toUpperCase().padEnd(7);
    const scope = context ? ` [${context}]` : "";
    const text = message instanceof Error ? message.message : String(message);

    process.stderr.write(`${time} ${label}${scope} ${text}\n`);
  }
}
