import * as vscode from "vscode";
import { AlertType, ScanResult } from "./types";

export class StatusBarManager {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
    this.item.command = "trustMeBro.showPanel";
    this.item.name = "Trust Me Bro";
    this.showIdle();
    this.item.show();
  }

  showScanning(current?: number, total?: number): void {
    this.item.text =
      current !== undefined && total !== undefined
        ? `$(loading~spin) Trust Me Bro: Scanning (${current}/${total})...`
        : "$(loading~spin) Trust Me Bro: Scanning...";
    this.item.tooltip = "Scanning dependencies...";
    this.item.backgroundColor = undefined;
  }

  update(results: ScanResult[]): void {
    const sosPkgs = new Set<string>();
    const warnPkgs = new Set<string>();

    for (const result of results) {
      for (const assessment of result.assessments) {
        const key = `${assessment.dependency.name}@${assessment.dependency.version}`;
        for (const alert of assessment.alerts) {
          if (alert.type === AlertType.SOS) sosPkgs.add(key);
          else warnPkgs.add(key);
        }
      }
    }

    const sosCount = sosPkgs.size;
    const warnCount = warnPkgs.size;
    const isStale = results.some((r) => r.isStale);
    const stale = isStale ? " (stale)" : "";

    if (sosCount > 0) {
      this.item.text = `$(shield) Trust Me Bro: ${sosCount} SOS${warnCount > 0 ? `, ${warnCount} warnings` : ""}${stale}`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
      this.item.tooltip = `${sosCount} compromised/vulnerable package(s)${stale}`;
    } else if (warnCount > 0) {
      this.item.text = `$(shield) Trust Me Bro: ${warnCount} warning${warnCount > 1 ? "s" : ""}${stale}`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      this.item.tooltip = `${warnCount} directional warning(s)${stale}`;
    } else {
      this.item.text = `$(shield) Trust Me Bro: All clear${stale}`;
      this.item.backgroundColor = undefined;
      this.item.tooltip = `All dependencies clean${stale}`;
    }
  }

  showIdle(): void {
    this.item.text = "$(shield) Trust Me Bro";
    this.item.tooltip = "Trust Me Bro — Dependency trust intelligence";
    this.item.backgroundColor = undefined;
  }

  showError(message: string): void {
    this.item.text = "$(shield) Trust Me Bro: Error";
    this.item.tooltip = message;
    this.item.backgroundColor = undefined;
  }

  dispose(): void {
    this.item.dispose();
  }
}
