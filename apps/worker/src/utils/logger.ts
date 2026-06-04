import pino, { type DestinationStream, type Logger } from "pino";
import { asWorkerError } from "@/errors";

export interface LoggerBindings {
  [key: string]: string
};

const REDACTED_PATHS = [
  "authorization",
  "*.authorization",
  "headers.authorization",
  "req.headers.authorization",
  "apiToken",
  "*.apiToken",
  "token",
  "*.token",
  "masterKey",
  "*.masterKey",
  "hmacKey",
  "*.hmacKey",
  "kek",
  "*.kek",
  "encrypted_pii",
  "*.encrypted_pii",
  "encrypted_pii.data",
  "*.encrypted_pii.data",
  "encrypted_dek",
  "*.encrypted_dek",
  "payload.data",
  "*.payload.data",
  "payload.email",
  "*.payload.email",
  "payload.full_name",
  "*.payload.full_name",
  "email",
  "*.email",
  "full_name",
  "*.full_name",
];

function serializeErrorForLog(error: unknown) {
  const normalizedError = asWorkerError(error);
  return {
    ...normalizedError.toProblem(),
    stack: normalizedError.stack,
  };
};

/**
 * Creates a Pino logger configured for worker-safe redaction and structured error serialization.
 * 
 * @param bindings - Optional static bindings merged into every log record.
 * @param destination - Optional Pino destination stream.
 * @returns Configured Pino logger instance.
 */
export function createWorkerLogger(
  bindings: LoggerBindings = {},
  destination?: DestinationStream
): Logger {
  const instance = pino(
    {
      level: process.env.LOG_LEVEL ?? "info",
      messageKey: "message",
      timestamp: pino.stdTimeFunctions.isoTime,
      base: {
        service: "compliance-worker",
        plane: "data"
      },
      redact: {
        paths: REDACTED_PATHS,
        censor: "[REDACTED]",
      },
      formatters: {
        level: (label) => ({ level: label })
      },
      serializers: {
        err: serializeErrorForLog
      },
    },
    destination
  )
  return Object.keys(bindings).length > 0 ? instance.child(bindings) : instance;
}

export const logger = createWorkerLogger();

/**
 * Returns a child logger bound to contextual fields.
 * 
 * @param bindings - Context bindings added to each emitted record.
 * @returns Child logger.
 */
export function getLogger(bindings: LoggerBindings): Logger {
  return logger.child(bindings);
}

/**
 * Logs and normalizes unknown errors using standardized worker error envelopes.
 *
 * @param loggerInstance - Logger to emit to.
 * @param error - Unknown error value.
 * @param message - Log message.
 * @param bindings - Additional structured context.
 * @returns Normalized `WorkerError`.
 */
export function logError(
  loggerInstace: Logger,
  error: unknown,
  message: string,
  bindings: LoggerBindings = {}
) {
  const normalizedError = asWorkerError(error);
  const level = normalizedError.fatal ? "fatal" : normalizedError.retryable ? "warn" : "fatal"
  loggerInstace[level]({ ...bindings, err: normalizedError });
  return normalizedError;
}

function terminate(logger: Logger, error: unknown, code: number) {
  const normalized = asWorkerError(error, {
    code: "RUNTIME_FATAL",
    title: "Fatal runtime error",
    detail: "A fatal runtime error reached the process boundary.",
    category: "runtime",
    fatal: true,
  });
  logError(logger, normalized, "Fatal runtime error reached process boundary");
  process.exit(code);
}

/**
 * Registers process-level fatal guards for unhandled rejections and uncaught exceptions.
 * 
 * @param logger - Root logger used to emit terminal failure diagnostics.
 * @returns vaild; installs listners on `process`.
 */
export function registerProcessGuard(logger: Logger) {
  process.on("unhandledRejection", (reason) => {
    terminate(logger, asWorkerError(reason, {
      code: "RUNTIME_UNHANDLED_REJECTION",
      title: "Unhandled promise rejections",
      detail: "An unhandled promise rejection reach the process boundary.",
      category: "runtime",
      retryable: false,
      fatal: true,
    }), 1)
  });

  process.on("uncaughtException", (error) => {
    terminate(logger, asWorkerError(error, {
      code: "RUNTIME_UNCAUGHT_EXCEPTION",
      title: "Uncaught exception",
      detail: "An uncaught exception reached the process boundary.",
      category: "runtime",
      retryable: false,
      fatal: true,
    }), 1);
  })
}

export const workerLogger = getLogger({ component: "worker" });
export const outboxLogger = getLogger({ component: "outbox" });