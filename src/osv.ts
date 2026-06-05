import * as https from "https";
import { Advisory, AffectedRange } from "./types";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const CONCURRENCY = 10;

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{
    package: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<Record<string, string>>;
    }>;
  }>;
}

interface OsvQueryResponse {
  vulns?: OsvVuln[];
}

function httpsPost(url: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
        timeout: 30000,
      },
      (res) => {
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          reject(new Error(`OSV API returned ${res.statusCode}`));
          res.resume();
          return;
        }
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks).toString()));
        res.on("error", reject);
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
    req.write(body);
    req.end();
  });
}

async function querySinglePackage(name: string): Promise<Advisory[]> {
  const body = JSON.stringify({ package: { name, ecosystem: "npm" } });
  const raw = await httpsPost(OSV_QUERY_URL, body);
  const response: OsvQueryResponse = JSON.parse(raw);
  return (response.vulns || []).map((v) => toAdvisory(v, name)).filter(Boolean) as Advisory[];
}

export async function queryAdvisories(
  packageNames: string[]
): Promise<Map<string, Advisory[]>> {
  const result = new Map<string, Advisory[]>();
  if (packageNames.length === 0) return result;

  for (let i = 0; i < packageNames.length; i += CONCURRENCY) {
    const batch = packageNames.slice(i, i + CONCURRENCY);
    const promises = batch.map(async (name) => {
      try {
        return { name, advisories: await querySinglePackage(name) };
      } catch {
        return { name, advisories: [] as Advisory[] };
      }
    });

    for (const { name, advisories } of await Promise.all(promises)) {
      result.set(name, advisories);
    }
  }

  return result;
}

function toAdvisory(vuln: OsvVuln, packageName: string): Advisory | null {
  const ranges = extractAffectedRanges(vuln, packageName);
  if (ranges.length === 0) return null;

  return {
    id: vuln.id,
    summary: vuln.summary || "No description available",
    severity: extractSeverity(vuln),
    affectedRanges: ranges,
  };
}

function extractAffectedRanges(vuln: OsvVuln, packageName: string): AffectedRange[] {
  const ranges: AffectedRange[] = [];
  if (!vuln.affected) return ranges;

  for (const affected of vuln.affected) {
    if (affected.package?.ecosystem !== "npm") continue;
    if (affected.package?.name !== packageName) continue;
    if (!affected.ranges) continue;

    for (const range of affected.ranges) {
      if (range.type !== "ECOSYSTEM" && range.type !== "SEMVER") continue;

      let currentIntroduced: string | null = null;
      for (const event of range.events) {
        if (event.introduced !== undefined) {
          currentIntroduced = event.introduced;
        } else if (event.fixed !== undefined && currentIntroduced !== null) {
          ranges.push({ introduced: currentIntroduced, fixed: event.fixed });
          currentIntroduced = null;
        } else if (event.last_affected !== undefined && currentIntroduced !== null) {
          // No fixed version available — treat as open-ended
          ranges.push({ introduced: currentIntroduced });
          currentIntroduced = null;
        }
      }
      if (currentIntroduced !== null) {
        ranges.push({ introduced: currentIntroduced });
      }
    }
  }

  return ranges;
}

function extractSeverity(vuln: OsvVuln): string {
  if (vuln.database_specific?.severity) {
    return vuln.database_specific.severity.toUpperCase();
  }

  if (vuln.severity && vuln.severity.length > 0) {
    for (const s of vuln.severity) {
      if (s.type === "CVSS_V3" || s.type === "CVSS_V4") {
        const score = parseFloat(s.score);
        if (!isNaN(score) && score >= 0 && score <= 10) {
          if (score >= 9.0) return "CRITICAL";
          if (score >= 7.0) return "HIGH";
          if (score >= 4.0) return "MEDIUM";
          if (score > 0) return "LOW";
        }
      }
    }
  }

  return "UNKNOWN";
}

export function isMalware(advisoryId: string): boolean {
  return advisoryId.startsWith("MAL-");
}
