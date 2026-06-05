import { vi, describe, it, expect } from "vitest";

vi.mock("vscode", () => ({}));

import { evaluate, evaluateAll } from "../src/evaluator";
import {
  Advisory,
  AffectedRange,
  AlertType,
  Dependency,
  TrustState,
} from "../src/types";

function dep(name: string, version: string, opts?: Partial<Dependency>): Dependency {
  return { name, version, isDirect: true, path: [name], dependencies: [], ...opts };
}

function advisory(
  id: string,
  ranges: AffectedRange[],
  severity = "HIGH"
): Advisory {
  return { id, summary: `Advisory ${id}`, severity, affectedRanges: ranges };
}

function range(introduced: string, fixed?: string): AffectedRange {
  return fixed ? { introduced, fixed } : { introduced };
}

// --- isVersionAffected (tested through evaluate → SOS) ---

describe("SOS alerts", () => {
  it("flags version inside affected range", () => {
    const result = evaluate(dep("lodash", "4.17.20"), [
      advisory("GHSA-1", [range("4.0.0", "4.17.21")]),
    ]);
    expect(result.trustState).toBe(TrustState.VULNERABLE);
    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });

  it("does not flag version at the fixed boundary (exclusive upper)", () => {
    const result = evaluate(dep("lodash", "4.17.21"), [
      advisory("GHSA-1", [range("4.0.0", "4.17.21")]),
    ]);
    expect(result.alerts.find((a) => a.type === AlertType.SOS)).toBeUndefined();
  });

  it("flags version when introduced is 0 (from the start)", () => {
    const result = evaluate(dep("foo", "1.0.0"), [
      advisory("GHSA-1", [range("0", "2.0.0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });

  it("flags all versions when no fixed exists (open-ended)", () => {
    const result = evaluate(dep("foo", "99.0.0"), [
      advisory("GHSA-1", [range("0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });

  it("does not flag version below introduced", () => {
    const result = evaluate(dep("foo", "3.0.0"), [
      advisory("GHSA-1", [range("5.0.0", "5.1.0")]),
    ]);
    expect(result.alerts.find((a) => a.type === AlertType.SOS)).toBeUndefined();
  });

  it("does not flag version above fixed", () => {
    const result = evaluate(dep("foo", "6.0.0"), [
      advisory("GHSA-1", [range("5.0.0", "5.1.0")]),
    ]);
    expect(result.alerts.find((a) => a.type === AlertType.SOS)).toBeUndefined();
  });

  it("handles multiple ranges in one advisory", () => {
    const result = evaluate(dep("foo", "3.5.0"), [
      advisory("GHSA-1", [range("1.0.0", "2.0.0"), range("3.0.0", "4.0.0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });
});

// --- DON'T UPGRADE ---

describe("DON'T UPGRADE alerts", () => {
  it("warns when versions above are affected", () => {
    const result = evaluate(dep("foo", "3.0.0"), [
      advisory("GHSA-1", [range("5.0.0", "5.5.0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.DONT_UPGRADE);
  });

  it("does not warn when affected range is entirely below", () => {
    const result = evaluate(dep("foo", "6.0.0"), [
      advisory("GHSA-1", [range("1.0.0", "2.0.0")]),
    ]);
    expect(result.alerts.find((a) => a.type === AlertType.DONT_UPGRADE)).toBeUndefined();
  });
});

// --- DON'T DOWNGRADE ---

describe("DON'T DOWNGRADE alerts", () => {
  it("warns when versions below are affected", () => {
    const result = evaluate(dep("foo", "5.0.0"), [
      advisory("GHSA-1", [range("1.0.0", "3.0.0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.DONT_DOWNGRADE);
  });

  it("warns when range with introduced=0 is entirely below", () => {
    const result = evaluate(dep("foo", "5.0.0"), [
      advisory("GHSA-1", [range("0", "4.0.0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.DONT_DOWNGRADE);
  });
});

// --- Trust state derivation ---

describe("trust state", () => {
  it("returns CLEAN when no advisories", () => {
    const result = evaluate(dep("foo", "1.0.0"), []);
    expect(result.trustState).toBe(TrustState.CLEAN);
  });

  it("returns CLEAN when version is not affected", () => {
    const result = evaluate(dep("foo", "2.0.0"), [
      advisory("GHSA-1", [range("1.0.0", "1.5.0")]),
    ]);
    expect(result.trustState).toBe(TrustState.CLEAN);
  });

  it("returns VULNERABLE for regular CVE SOS", () => {
    const result = evaluate(dep("foo", "1.2.0"), [
      advisory("GHSA-1", [range("1.0.0", "1.5.0")]),
    ]);
    expect(result.trustState).toBe(TrustState.VULNERABLE);
  });

  it("returns COMPROMISED for malware SOS", () => {
    const result = evaluate(dep("foo", "1.2.0"), [
      advisory("MAL-2024-1234", [range("0")]),
    ]);
    expect(result.trustState).toBe(TrustState.COMPROMISED);
  });

  it("COMPROMISED wins when both malware and CVE present", () => {
    const result = evaluate(dep("foo", "1.2.0"), [
      advisory("GHSA-1", [range("1.0.0", "2.0.0")]),
      advisory("MAL-2024-1", [range("0")]),
    ]);
    expect(result.trustState).toBe(TrustState.COMPROMISED);
  });
});

// --- Edge cases ---

describe("edge cases", () => {
  it("handles invalid version gracefully", () => {
    const result = evaluate(dep("foo", "not-a-version"), [
      advisory("GHSA-1", [range("0", "1.0.0")]),
    ]);
    expect(result.trustState).toBe(TrustState.CLEAN);
    expect(result.alerts).toHaveLength(0);
  });

  it("handles pre-release introduced version", () => {
    const result = evaluate(dep("foo", "5.5.0"), [
      advisory("GHSA-1", [range("5.0.0-alpha.0", "5.13.2")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });

  it("version at introduced boundary is affected (inclusive)", () => {
    const result = evaluate(dep("foo", "4.0.0"), [
      advisory("GHSA-1", [range("4.0.0", "4.5.0")]),
    ]);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });

  it("multiple advisories produce multiple alerts", () => {
    const result = evaluate(dep("foo", "1.5.0"), [
      advisory("GHSA-1", [range("1.0.0", "2.0.0")]),
      advisory("GHSA-2", [range("1.0.0", "1.8.0")]),
    ]);
    expect(result.alerts).toHaveLength(2);
    expect(result.alerts.every((a) => a.type === AlertType.SOS)).toBe(true);
  });

  it("SOS takes priority over DON'T UPGRADE for same advisory", () => {
    // If user is affected, alert should be SOS, not DON'T UPGRADE
    const result = evaluate(dep("foo", "1.5.0"), [
      advisory("GHSA-1", [range("1.0.0", "2.0.0")]),
    ]);
    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0].type).toBe(AlertType.SOS);
  });
});

// --- evaluateAll ---

describe("evaluateAll", () => {
  it("walks nested dependency tree", () => {
    const deps: Dependency[] = [
      dep("parent", "1.0.0", {
        dependencies: [dep("child", "2.0.0", { isDirect: false, path: ["parent", "child"] })],
      }),
    ];
    const advisoryMap = new Map([
      ["child", [advisory("GHSA-1", [range("1.0.0", "3.0.0")])]],
    ]);

    const results = evaluateAll(deps, advisoryMap);
    expect(results).toHaveLength(2);

    const parentResult = results.find((r) => r.dependency.name === "parent");
    const childResult = results.find((r) => r.dependency.name === "child");
    expect(parentResult?.trustState).toBe(TrustState.CLEAN);
    expect(childResult?.alerts[0].type).toBe(AlertType.SOS);
  });

  it("returns empty for no deps", () => {
    expect(evaluateAll([], new Map())).toHaveLength(0);
  });
});
