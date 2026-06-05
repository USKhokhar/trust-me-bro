import * as vscode from "vscode";

let channel: vscode.OutputChannel;

export function initLog(): vscode.OutputChannel {
  channel = vscode.window.createOutputChannel("Trust Me Bro");
  return channel;
}

export function log(msg: string): void {
  const ts = new Date().toISOString().slice(11, 23);
  channel?.appendLine(`[${ts}] ${msg}`);
}
