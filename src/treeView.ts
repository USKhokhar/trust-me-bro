import * as vscode from "vscode";
import * as path from "path";
import { AlertType, ScanResult, TrustAssessment, TrustState } from "./types";

type TreeElement = RootItem | DependencyItem | AlertItem;

class RootItem {
  constructor(public readonly label: string, public readonly result: ScanResult) {}
}

class DependencyItem {
  constructor(public readonly assessment: TrustAssessment, public readonly rootLabel: string) {}
}

class AlertItem {
  constructor(
    public readonly type: AlertType,
    public readonly advisoryId: string,
    public readonly summary: string,
    public readonly severity: string
  ) {}
}

export class TrustTreeProvider implements vscode.TreeDataProvider<TreeElement> {
  private results: ScanResult[] = [];
  private assessmentIndex = new Map<string, TrustAssessment>();
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<TreeElement | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  update(results: ScanResult[]): void {
    this.results = results;
    this.assessmentIndex.clear();
    for (const result of results) {
      for (const a of result.assessments) {
        this.assessmentIndex.set(`${a.dependency.name}@${a.dependency.version}`, a);
      }
    }
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeElement): vscode.TreeItem {
    if (element instanceof RootItem) return this.buildRootItem(element);
    if (element instanceof DependencyItem) return this.buildDepItem(element);
    return this.buildAlertItem(element);
  }

  getChildren(element?: TreeElement): TreeElement[] {
    if (!element) {
      if (this.results.length === 0) return [];
      if (this.results.length === 1) return this.getDepsForResult(this.results[0]);
      return this.results.map(
        (r) => new RootItem(path.basename(r.root.uri.fsPath) + ` (${r.root.lockfileType})`, r)
      );
    }
    if (element instanceof RootItem) return this.getDepsForResult(element.result);
    if (element instanceof DependencyItem) {
      return element.assessment.alerts.map(
        (a) => new AlertItem(a.type, a.advisory.id, a.advisory.summary, a.advisory.severity)
      );
    }
    return [];
  }

  private getDepsForResult(result: ScanResult): TreeElement[] {
    return result.assessments
      .filter((a) => a.dependency.isDirect)
      .map((a) => new DependencyItem(a, path.basename(result.root.uri.fsPath)))
      .sort((a, b) => this.alertScore(b.assessment) - this.alertScore(a.assessment));
  }

  private alertScore(assessment: TrustAssessment): number {
    if (assessment.alerts.some((a) => a.type === AlertType.SOS)) return 3;
    if (assessment.alerts.some((a) => a.type === AlertType.DONT_UPGRADE)) return 2;
    if (assessment.alerts.some((a) => a.type === AlertType.DONT_DOWNGRADE)) return 1;
    return 0;
  }

  private buildRootItem(item: RootItem): vscode.TreeItem {
    const issueCount = item.result.assessments.filter((a) => a.alerts.length > 0).length;
    const treeItem = new vscode.TreeItem(item.label, vscode.TreeItemCollapsibleState.Expanded);
    treeItem.description = issueCount > 0 ? `${issueCount} issue${issueCount > 1 ? "s" : ""}` : "all clear";
    treeItem.iconPath = issueCount > 0
      ? new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground"))
      : new vscode.ThemeIcon("check", new vscode.ThemeColor("charts.green"));
    return treeItem;
  }

  private buildDepItem(item: DependencyItem): vscode.TreeItem {
    const dep = item.assessment.dependency;
    const alerts = item.assessment.alerts;
    const hasSos = alerts.some((a) => a.type === AlertType.SOS);
    const hasDontUpgrade = alerts.some((a) => a.type === AlertType.DONT_UPGRADE);
    const hasDontDowngrade = alerts.some((a) => a.type === AlertType.DONT_DOWNGRADE);

    const treeItem = new vscode.TreeItem(
      `${dep.name}@${dep.version}`,
      alerts.length > 0 ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None
    );

    if (!dep.isDirect && dep.path.length > 1) {
      treeItem.description = dep.path.slice(0, -1).join(" → ");
    }

    if (hasSos) {
      treeItem.iconPath = new vscode.ThemeIcon("error", new vscode.ThemeColor("list.errorForeground"));
      treeItem.description = item.assessment.trustState === TrustState.COMPROMISED
        ? "SOS — COMPROMISED"
        : "SOS — VULNERABLE";
    } else if (hasDontUpgrade) {
      treeItem.iconPath = new vscode.ThemeIcon("arrow-up", new vscode.ThemeColor("list.warningForeground"));
      treeItem.description = "DON'T UPGRADE";
    } else if (hasDontDowngrade) {
      treeItem.iconPath = new vscode.ThemeIcon("arrow-down", new vscode.ThemeColor("list.warningForeground"));
      treeItem.description = "DON'T DOWNGRADE";
    } else {
      treeItem.iconPath = new vscode.ThemeIcon("check", new vscode.ThemeColor("charts.green"));
    }

    const transitiveIssues = this.countTransitiveIssues(item.assessment);
    if (transitiveIssues > 0 && !hasSos && !hasDontUpgrade && !hasDontDowngrade) {
      treeItem.description = `${transitiveIssues} transitive issue${transitiveIssues > 1 ? "s" : ""}`;
      treeItem.iconPath = new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground"));
      treeItem.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
    }

    return treeItem;
  }

  private buildAlertItem(item: AlertItem): vscode.TreeItem {
    const prefix =
      item.type === AlertType.SOS ? "SOS"
      : item.type === AlertType.DONT_UPGRADE ? "DON'T UPGRADE"
      : "DON'T DOWNGRADE";

    const treeItem = new vscode.TreeItem(
      `${item.advisoryId}: ${item.summary}`,
      vscode.TreeItemCollapsibleState.None
    );
    treeItem.description = `${prefix} · ${item.severity}`;
    treeItem.tooltip = new vscode.MarkdownString(
      `**${item.advisoryId}**\n\n${item.summary}\n\nSeverity: ${item.severity}\n\n[View on OSV.dev](https://osv.dev/vulnerability/${item.advisoryId})`
    );
    treeItem.iconPath = item.type === AlertType.SOS
      ? new vscode.ThemeIcon("flame", new vscode.ThemeColor("list.errorForeground"))
      : new vscode.ThemeIcon("info", new vscode.ThemeColor("list.warningForeground"));

    return treeItem;
  }

  private countTransitiveIssues(assessment: TrustAssessment): number {
    let count = 0;
    const walk = (deps: typeof assessment.dependency.dependencies) => {
      for (const dep of deps) {
        const a = this.assessmentIndex.get(`${dep.name}@${dep.version}`);
        if (a && a.alerts.length > 0) count++;
        walk(dep.dependencies);
      }
    };
    walk(assessment.dependency.dependencies);
    return count;
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
  }
}
