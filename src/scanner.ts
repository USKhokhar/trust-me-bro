import * as vscode from "vscode";
import { parseDependencyTree, collectPackageNames } from "./lockfile";
import { queryAdvisories } from "./osv";
import { AdvisoryCache } from "./cache";
import { evaluateAll } from "./evaluator";
import { Advisory, ScanResult, WorkspaceRoot } from "./types";
import { log } from "./log";

export class Scanner {
  private readonly cache: AdvisoryCache;

  constructor(cache: AdvisoryCache) {
    this.cache = cache;
  }

  async scan(
    root: WorkspaceRoot,
    onProgress?: (current: number, total: number) => void
  ): Promise<ScanResult> {
    log(`Scan started for ${root.uri.fsPath} (${root.lockfileType})`);

    let deps;
    try {
      deps = await parseDependencyTree(root);
      log(`Parsed ${deps.length} direct dependencies`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`ERROR parsing deps: ${msg}`);
      vscode.window.showWarningMessage(`Trust Me Bro: Failed to parse dependencies: ${msg}`);
      return { root, assessments: [], lastChecked: new Date(), isStale: false };
    }

    if (deps.length === 0) {
      log("No dependencies found");
      return { root, assessments: [], lastChecked: new Date(), isStale: false };
    }

    const allNames = Array.from(collectPackageNames(deps));
    const needsFetch = this.cache.getExpiredPackages(allNames);
    let isStale = false;

    log(`Unique packages: ${allNames.length}, need fetch: ${needsFetch.length}`);

    if (needsFetch.length > 0) {
      try {
        const fetched = await queryAdvisories(needsFetch);
        let done = allNames.length - needsFetch.length;
        let totalAdvisories = 0;
        for (const [name, advisories] of fetched) {
          this.cache.set(name, advisories);
          if (advisories.length > 0) {
            log(`  ${name}: ${advisories.length} advisories`);
            totalAdvisories += advisories.length;
          }
          done++;
          onProgress?.(done, allNames.length);
        }
        log(`Fetch complete: ${totalAdvisories} advisories across ${fetched.size} packages`);
        this.cache.save();
      } catch (err) {
        log(`ERROR fetching: ${err instanceof Error ? err.message : err}`);
        isStale = true;
      }
    }

    const advisoryMap = new Map<string, Advisory[]>();
    for (const name of allNames) {
      const cached = this.cache.get(name);
      if (cached) {
        advisoryMap.set(name, cached);
      } else {
        const stale = this.cache.getStale(name);
        if (stale) {
          advisoryMap.set(name, stale.advisories);
          isStale = true;
        } else {
          advisoryMap.set(name, []);
        }
      }
    }

    const assessments = evaluateAll(deps, advisoryMap);
    const withAlerts = assessments.filter((a) => a.alerts.length > 0);
    log(`Done: ${assessments.length} deps, ${withAlerts.length} with alerts`);
    for (const a of withAlerts) {
      log(`  ${a.dependency.name}@${a.dependency.version}: ${a.alerts.map((al) => al.type).join(", ")}`);
    }

    return { root, assessments, lastChecked: new Date(), isStale };
  }
}
