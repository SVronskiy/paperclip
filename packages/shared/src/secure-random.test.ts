import { afterEach, describe, expect, it, vi } from "vitest";
import {
  secureJitter,
  secureRandom,
  secureRandomHex,
  secureRandomId,
  secureRandomInt,
} from "./secure-random.js";

describe("secure random helpers", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("never touches Math.random", () => {
    const spy = vi.spyOn(Math, "random");
    secureRandom();
    secureRandomInt(10);
    secureRandomHex(4);
    secureRandomId(6);
    secureJitter(0.25);
    expect(spy).not.toHaveBeenCalled();
  });

  it("secureRandom stays in [0, 1) and takes both extremes of the generator", () => {
    for (let index = 0; index < 1000; index += 1) {
      const value = secureRandom();
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(1);
    }
    vi.stubGlobal("crypto", { getRandomValues: (words: Uint32Array) => { words.fill(0); return words; } });
    expect(secureRandom()).toBe(0);
    vi.stubGlobal("crypto", { getRandomValues: (words: Uint32Array) => { words.fill(0xffffffff); return words; } });
    expect(secureRandom()).toBeLessThan(1);
    expect(secureRandom()).toBeGreaterThan(0.9999999999999);
  });

  it("secureRandomInt covers the range and rejects bad bounds", () => {
    const seen = new Set<number>();
    for (let index = 0; index < 500; index += 1) seen.add(secureRandomInt(6));
    expect([...seen].sort()).toEqual([0, 1, 2, 3, 4, 5]);
    expect(secureRandomInt(1)).toBe(0);
    expect(() => secureRandomInt(0)).toThrow(RangeError);
    expect(() => secureRandomInt(1.5)).toThrow(RangeError);
  });

  it("secureRandomInt removes modulo bias by rejecting the top of the range", () => {
    const words = [0xffffffff, 7];
    vi.stubGlobal("crypto", { getRandomValues: (target: Uint32Array) => { target[0] = words.shift()!; return target; } });
    // 2^32 % 6 = 4, so values >= 2^32 - 4 must be redrawn.
    expect(secureRandomInt(6)).toBe(1);
    expect(words).toEqual([]);
  });

  it("secureRandomHex and secureRandomId have the requested shape", () => {
    expect(secureRandomHex(8)).toMatch(/^[0-9a-f]{16}$/);
    expect(secureRandomId(10)).toMatch(/^[0-9a-z]{10}$/);
    expect(secureRandomHex(8)).not.toBe(secureRandomHex(8));
  });

  it("secureJitter stays inside the ratio", () => {
    for (let index = 0; index < 500; index += 1) {
      const factor = secureJitter(0.25);
      expect(factor).toBeGreaterThanOrEqual(0.75);
      expect(factor).toBeLessThan(1.25);
    }
  });

  it("fails closed when no secure generator exists", () => {
    vi.stubGlobal("crypto", undefined);
    expect(() => secureRandom()).toThrow(/secure random/);
  });
});
