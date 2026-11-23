/**
 * Cryptographically secure random helpers.
 *
 * Use these instead of the non-secure built-in generator anywhere in product code, including
 * identifiers, temporary names, retry jitter and UI effects. They are built on
 * `globalThis.crypto.getRandomValues`, which exists in Node.js and in every
 * browser (including non-secure contexts, unlike `crypto.randomUUID()`).
 */

function getCrypto(): Crypto {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function") {
    // Fail closed: never fall back to a predictable generator.
    throw new Error("A secure random number generator (crypto.getRandomValues) is not available");
  }
  return cryptoApi;
}

/** A uniformly distributed float in [0, 1) with 53 bits of randomness; a drop-in for the built-in non-secure generator. */
export function secureRandom(): number {
  const words = new Uint32Array(2);
  getCrypto().getRandomValues(words);
  // 27 + 26 = 53 significant bits, the full precision of a double.
  return ((words[0]! >>> 5) * 67_108_864 + (words[1]! >>> 6)) / 9_007_199_254_740_992;
}

/** A uniformly distributed integer in [0, maxExclusive), without modulo bias. */
export function secureRandomInt(maxExclusive: number): number {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 2 ** 32) {
    throw new RangeError("maxExclusive must be an integer between 1 and 2^32");
  }
  if (maxExclusive === 1) return 0;
  const word = new Uint32Array(1);
  const limit = 2 ** 32 - (2 ** 32 % maxExclusive);
  do {
    getCrypto().getRandomValues(word);
  } while (word[0]! >= limit);
  return word[0]! % maxExclusive;
}

/** `byteLength` random bytes encoded as lowercase hex (2 characters per byte). */
export function secureRandomHex(byteLength = 8): string {
  if (!Number.isInteger(byteLength) || byteLength < 1 || byteLength > 1024) {
    throw new RangeError("byteLength must be an integer between 1 and 1024");
  }
  const bytes = new Uint8Array(byteLength);
  getCrypto().getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** A random lowercase base-36 identifier of `length` characters. */
export function secureRandomId(length = 8): string {
  if (!Number.isInteger(length) || length < 1 || length > 256) {
    throw new RangeError("length must be an integer between 1 and 256");
  }
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
  let id = "";
  for (let index = 0; index < length; index += 1) id += alphabet[secureRandomInt(alphabet.length)];
  return id;
}

/** A multiplier in [1 - ratio, 1 + ratio) for spreading retry delays; e.g. `delay * secureJitter(0.25)`. */
export function secureJitter(ratio: number): number {
  return 1 + (secureRandom() * 2 - 1) * ratio;
}
