import * as fs from "fs";
import * as path from "path";
import { Advisory, CacheEntry, CacheStore } from "./types";

const CACHE_VERSION = 1;

export class AdvisoryCache {
  private store: CacheStore;
  private readonly filePath: string;
  private ttlMs: number;

  constructor(storagePath: string, ttlMinutes: number) {
    this.filePath = path.join(storagePath, "advisory-cache.json");
    this.ttlMs = ttlMinutes * 60 * 1000;
    this.store = this.load();
  }

  get(packageName: string): Advisory[] | null {
    const entry = this.store.entries[packageName];
    if (!entry || this.isExpired(entry)) return null;
    return entry.advisories;
  }

  getStale(packageName: string): { advisories: Advisory[]; fetchedAt: number } | null {
    const entry = this.store.entries[packageName];
    if (!entry) return null;
    return { advisories: entry.advisories, fetchedAt: entry.fetchedAt };
  }

  set(packageName: string, advisories: Advisory[]): void {
    this.store.entries[packageName] = { packageName, advisories, fetchedAt: Date.now() };
  }

  save(): void {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this.store), "utf-8");
    } catch {
      // non-fatal
    }
  }

  getExpiredPackages(packageNames: string[]): string[] {
    return packageNames.filter((name) => {
      const entry = this.store.entries[name];
      return !entry || this.isExpired(entry);
    });
  }

  updateTtl(ttlMinutes: number): void {
    this.ttlMs = ttlMinutes * 60 * 1000;
  }

  clear(): void {
    this.store = { version: CACHE_VERSION, entries: {} };
    this.save();
  }

  private isExpired(entry: CacheEntry): boolean {
    return Date.now() - entry.fetchedAt > this.ttlMs;
  }

  private load(): CacheStore {
    try {
      if (fs.existsSync(this.filePath)) {
        const parsed: CacheStore = JSON.parse(fs.readFileSync(this.filePath, "utf-8"));
        if (parsed.version === CACHE_VERSION) return parsed;
      }
    } catch {
      // corrupt cache — start fresh
    }
    return { version: CACHE_VERSION, entries: {} };
  }
}
