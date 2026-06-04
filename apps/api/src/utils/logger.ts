import pino, { type DestinationStream, type Logger } from "pino";
import { asApiError } from "../errors";

const REDACT_PATHS = [
  "authorization",
  "*.authorization",
  "headers.authorization",
  "req.headers.authorization",
  "body.email",
  "*.body.email",
  "payload.email",
  "*.payload.email",
  "payload.full_name",
  "*.payload.full_name",
  "signature.signatureBase64",
  "*.signature.signatureBase64",
];

function serializeErrorForLog(error: unknown) {
  const normalized = asApiError(error);
  return {
    ...normalized.toProblem(),
    stack: normalized.stack,
  };
}

export interface LoggerBindings {
  [key: string]: unknown;
}

/**
 * Creates a Pino logger configured for control-plane redaction and structured API errors.
 *
 * @param bindings - Optional static bindings.
 * @param destination - Optional destination stream.
 * @returns Configured logger instance.
 */
export function createApiLogger(bindings: LoggerBindings = {}, destination?: DestinationStream): Logger {
  const instance = pino(
    {
      level: process.env.LOG_LEVEL ?? "info",
      messageKey: "message",
      timestamp: pino.stdTimeFunctions.isoTime,
      base: {
        service: "dpdp-compliance-api",
        plane: "control",
      },
      redact: {
        paths: REDACT_PATHS,
        censor: "[REDACTED]",
      },
      formatters: {
        level: (label: string) => ({ level: label }),
      },
      serializers: {
        err: serializeErrorForLog,
      },
    },
    destination
  );

  return Object.keys(bindings).length > 0 ? instance.child(bindings) : instance;
}

export const logger = createApiLogger();

/**
 * Returns a child logger enriched with request/module context.
 *
 * @param bindings - Context fields to bind.
 * @returns Child logger instance.
 */
export function getLogger(bindings: LoggerBindings): Logger {
  return logger.child(bindings);
}

/**
 * Logs and normalizes unknown errors using the API error envelope.
 *
 * @param loggerInstance - Logger to emit to.
 * @param error - Unknown thrown value.
 * @param message - Message text.
 * @param bindings - Additional structured context.
 * @returns Normalized `ApiError`.
 */
export function logError(loggerInstance: Logger, error: unknown, message: string, bindings: LoggerBindings = {}) {
  const normalized = asApiError(error);
  const level = normalized.fatal ? "fatal" : normalized.retryable ? "warn" : normalized.status >= 500 ? "error" : "warn";
  loggerInstance[level]({ ...bindings, err: normalized }, message);
  return normalized;
}
