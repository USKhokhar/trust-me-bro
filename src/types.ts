import * as vscode from "vscode";

export enum TrustState {
  COMPROMISED = "compromised",
  VULNERABLE = "vulnerable",
  CLEAN = "clean",
}

export enum AlertType {
  SOS = "sos",
  DONT_UPGRADE = "dont_upgrade",
  DONT_DOWNGRADE = "dont_downgrade",
}

export type LockfileType = "npm" | "yarn" | "pnpm";

export interface Dependency {
  name: string;
  version: string;
  isDirect: boolean;
  path: string[];
  dependencies: Dependency[];
}

export interface AffectedRange {
  introduced: string;
  fixed?: string;
}

export interface Advisory {
  id: string;
  summary: string;
  severity: string;
  affectedRanges: AffectedRange[];
}

export interface Alert {
  type: AlertType;
  advisory: Advisory;
}

export interface TrustAssessment {
  dependency: Dependency;
  trustState: TrustState;
  alerts: Alert[];
  advisories: Advisory[];
}

export interface WorkspaceRoot {
  uri: vscode.Uri;
  lockfileType: LockfileType;
  lockfilePath: string;
}

export interface ScanResult {
  root: WorkspaceRoot;
  assessments: TrustAssessment[];
  lastChecked: Date;
  isStale: boolean;
}

export interface CacheEntry {
  packageName: string;
  advisories: Advisory[];
  fetchedAt: number;
}

export interface CacheStore {
  version: number;
  entries: Record<string, CacheEntry>;
}
