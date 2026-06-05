import * as semver from "semver";
import {
  Advisory,
  AffectedRange,
  Alert,
  AlertType,
  Dependency,
  TrustAssessment,
  TrustState,
} from "./types";
import { isMalware } from "./osv";

export function evaluate(dep: Dependency, advisories: Advisory[]): TrustAssessment {
  const version = semver.valid(semver.coerce(dep.version));
  if (!version || advisories.length === 0) {
    return { dependency: dep, trustState: TrustState.CLEAN, alerts: [], advisories: [] };
  }

  const alerts: Alert[] = [];
  const matchedAdvisories: Advisory[] = [];

  for (const advisory of advisories) {
    const userAffected = isVersionAffected(version, advisory.affectedRanges);
    const aboveAffected = hasAffectedVersionsAbove(version, advisory.affectedRanges);
    const belowAffected = hasAffectedVersionsBelow(version, advisory.affectedRanges);

    if (userAffected) {
      alerts.push({ type: AlertType.SOS, advisory });
      matchedAdvisories.push(advisory);
    } else if (aboveAffected) {
      alerts.push({ type: AlertType.DONT_UPGRADE, advisory });
      matchedAdvisories.push(advisory);
    } else if (belowAffected) {
      alerts.push({ type: AlertType.DONT_DOWNGRADE, advisory });
      matchedAdvisories.push(advisory);
    }
  }

  return {
    dependency: dep,
    trustState: deriveTrustState(alerts),
    alerts,
    advisories: matchedAdvisories,
  };
}

// Range: [introduced, fixed) — "0" means from the start, no fixed = open-ended
function isVersionAffected(version: string, ranges: AffectedRange[]): boolean {
  for (const range of ranges) {
    const introduced = normalizeVersion(range.introduced);
    if (!introduced) continue;

    const gte = range.introduced === "0" || semver.gte(version, introduced);
    if (!gte) continue;

    if (!range.fixed) return true;

    const fixed = semver.valid(semver.coerce(range.fixed));
    if (!fixed) continue;

    if (semver.lt(version, fixed)) return true;
  }
  return false;
}

function hasAffectedVersionsAbove(version: string, ranges: AffectedRange[]): boolean {
  for (const range of ranges) {
    const introduced = normalizeVersion(range.introduced);
    if (!introduced) continue;

    if (semver.gt(introduced, version)) return true;

    if (!range.fixed) continue;
    const fixed = semver.valid(semver.coerce(range.fixed));
    if (!fixed) continue;

    if (semver.gt(fixed, version) && semver.gt(introduced, version)) return true;
  }
  return false;
}

function hasAffectedVersionsBelow(version: string, ranges: AffectedRange[]): boolean {
  for (const range of ranges) {
    const introduced = normalizeVersion(range.introduced);
    if (!introduced) continue;

    if (range.introduced === "0" || semver.lt(introduced, version)) {
      if (range.fixed) {
        const fixed = semver.valid(semver.coerce(range.fixed));
        if (fixed && semver.lte(fixed, version)) return true;
      }
    }
  }
  return false;
}

function normalizeVersion(v: string): string | null {
  if (v === "0") return "0.0.0";
  return semver.valid(semver.coerce(v));
}

function deriveTrustState(alerts: Alert[]): TrustState {
  const sosAlerts = alerts.filter((a) => a.type === AlertType.SOS);
  if (sosAlerts.length === 0) return TrustState.CLEAN;

  const hasCompromise = sosAlerts.some((a) => isMalware(a.advisory.id));
  return hasCompromise ? TrustState.COMPROMISED : TrustState.VULNERABLE;
}

export function evaluateAll(
  deps: Dependency[],
  advisoryMap: Map<string, Advisory[]>
): TrustAssessment[] {
  const assessments: TrustAssessment[] = [];

  function walk(dep: Dependency) {
    assessments.push(evaluate(dep, advisoryMap.get(dep.name) || []));
    for (const child of dep.dependencies) walk(child);
  }

  for (const dep of deps) walk(dep);
  return assessments;
}
