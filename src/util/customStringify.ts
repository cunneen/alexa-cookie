
export function customStringify(
  /*            biome-ignore lint/suspicious/noExplicitAny: JSON.stringify accepts any */
  v: any,
  _unused?: unknown,
  intent?: string | number | undefined) {
  const cache = new Map();
  return JSON.stringify(
    v,
    (_key, value) => {
      if (typeof value === "object" && value !== null) {
        if (cache.get(value)) {
          // Circular reference found, discard key
          return;
        }
        // Store value in our map
        cache.set(value, true);
      }
      if (Buffer.isBuffer(value)) {
        // Buffers not relevant to be logged, ignore
        return;
      }
      return value;
    },
    intent
  );
}
