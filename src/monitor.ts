import * as vscode from "vscode";
import { detectWorkspaceRoots } from "./lockfile";
import { Scanner } from "./scanner";
import { AdvisoryCache } from "./cache";
import { StatusBarManager } from "./statusBar";
import { TrustTreeProvider } from "./treeView";
import { notifySosAlerts, resetShownAlerts } from "./notifications";
import { ScanResult } from "./types";
import { log } from "./log";

export class Monitor implements vscode.Disposable {
  private readonly scanner: Scanner;
  private readonly cache: AdvisoryCache;
  private readonly statusBar: StatusBarManager;
  private readonly treeProvider: TrustTreeProvider;
  private readonly disposables: vscode.Disposable[] = [];
  private results: ScanResult[] = [];
  private pollTimer: NodeJS.Timeout | null = null;
  private scanning = false;

  constructor(
    scanner: Scanner,
    cache: AdvisoryCache,
    statusBar: StatusBarManager,
    treeProvider: TrustTreeProvider
  ) {
    this.scanner = scanner;
    this.cache = cache;
    this.statusBar = statusBar;
    this.treeProvider = treeProvider;
  }

  start(): void {
    this.scanAll();
    this.watchLockfiles();
    this.startPollTimer();

    this.disposables.push(
      vscode.workspace.onDidChangeWorkspaceFolders(() => {
        resetShownAlerts();
        this.scanAll();
      }),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration("trustMeBro.pollInterval")) {
          const minutes = vscode.workspace
            .getConfiguration("trustMeBro")
            .get<number>("pollInterval", 30);
          this.cache.updateTtl(minutes);
          this.restartPollTimer();
        }
      })
    );
  }

  async scanAll(): Promise<void> {
    if (this.scanning) return;
    this.scanning = true;

    try {
      const roots = detectWorkspaceRoots();
      if (roots.length === 0) {
        this.statusBar.showIdle();
        this.treeProvider.update([]);
        this.results = [];
        return;
      }

      this.statusBar.showScanning();
      const newResults: ScanResult[] = [];

      for (const root of roots) {
        const result = await this.scanner.scan(root, (current, total) => {
          this.statusBar.showScanning(current, total);
        });
        newResults.push(result);
        notifySosAlerts([result]);
      }

      this.results = newResults;
      this.statusBar.update(this.results);
      this.treeProvider.update(this.results);
    } catch (err) {
      this.statusBar.showError(err instanceof Error ? err.message : String(err));
    } finally {
      this.scanning = false;
    }
  }

  async forceRefresh(): Promise<void> {
    log("Force refresh — clearing cache");
    this.cache.clear();
    resetShownAlerts();
    await this.scanAll();
  }

  private watchLockfiles(): void {
    const watcher = vscode.workspace.createFileSystemWatcher(
      "**/{package-lock.json,yarn.lock,pnpm-lock.yaml}"
    );

    const onChange = () => {
      resetShownAlerts();
      this.scanAll();
    };

    this.disposables.push(
      watcher.onDidChange(onChange),
      watcher.onDidCreate(onChange),
      watcher.onDidDelete(onChange),
      watcher
    );
  }

  private getPollIntervalMs(): number {
    const minutes = vscode.workspace.getConfiguration("trustMeBro").get<number>("pollInterval", 30);
    return Math.max(1, minutes) * 60 * 1000;
  }

  private startPollTimer(): void {
    this.pollTimer = setInterval(() => this.scanAll(), this.getPollIntervalMs());
  }

  private restartPollTimer(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.startPollTimer();
  }

  dispose(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    for (const d of this.disposables) d.dispose();
  }
}
