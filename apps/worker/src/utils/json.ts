type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => sortJson(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort((left, right) => left.localeCompare(right))
        .map((key) => [key, sortJson((value as Record<string, JsonValue>)[key]!)])
    );
  }

  return value;
}


/**
 * Serializes unknown input into deterministic JSON text by sorting object keys recursively.
 *
 * Non-JSON values are first normalized using native `JSON.stringify` semantics, then canonicalized.
 */
export function canonicalJsonStringify(value: unknown): string {
  const firstPass = JSON.stringify(value);
  if (firstPass === undefined) {
    throw new TypeError("Value is not JSON-serializable.");
  }

  const parsed = JSON.parse(firstPass) as JsonValue;
  return JSON.stringify(sortJson(parsed));
}

