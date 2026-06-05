import * as vscode from "vscode";
import { AdvisoryCache } from "./cache";
import { Scanner } from "./scanner";
import { StatusBarManager } from "./statusBar";
import { TrustTreeProvider } from "./treeView";
import { Monitor } from "./monitor";
import { initLog } from "./log";

export function activate(context: vscode.ExtensionContext) {
  const outputChannel = initLog();
  context.subscriptions.push(outputChannel);

  const pollInterval = vscode.workspace
    .getConfiguration("trustMeBro")
    .get<number>("pollInterval", 30);

  const cache = new AdvisoryCache(context.globalStorageUri.fsPath, pollInterval);
  const scanner = new Scanner(cache);
  const statusBar = new StatusBarManager();
  const treeProvider = new TrustTreeProvider();
  const monitor = new Monitor(scanner, cache, statusBar, treeProvider);

  const treeView = vscode.window.createTreeView("trustMeBro.dependencyTree", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  context.subscriptions.push(
    statusBar,
    treeProvider,
    treeView,
    monitor,
    vscode.commands.registerCommand("trustMeBro.scanDependencies", () => monitor.scanAll()),
    vscode.commands.registerCommand("trustMeBro.showPanel", () => {
      vscode.commands.executeCommand("trustMeBro.dependencyTree.focus");
    }),
    vscode.commands.registerCommand("trustMeBro.forceRefresh", () => monitor.forceRefresh()),
  );

  monitor.start();
}

export function deactivate() {}
