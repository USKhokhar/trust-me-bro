import * as vscode from "vscode";
import { AlertType, ScanResult } from "./types";

const shownSosAlerts = new Set<string>();

export function notifySosAlerts(results: ScanResult[]): void {
  for (const result of results) {
    for (const assessment of result.assessments) {
      for (const alert of assessment.alerts) {
        if (alert.type !== AlertType.SOS) continue;

        const key = `${assessment.dependency.name}@${assessment.dependency.version}:${alert.advisory.id}`;
        if (shownSosAlerts.has(key)) continue;
        shownSosAlerts.add(key);

        const dep = assessment.dependency;
        vscode.window
          .showErrorMessage(
            `SOS: ${dep.name}@${dep.version} is ${assessment.trustState}! ${alert.advisory.summary}`,
            "View Details",
            "Dismiss"
          )
          .then((action) => {
            if (action === "View Details") {
              vscode.env.openExternal(
                vscode.Uri.parse(`https://osv.dev/vulnerability/${alert.advisory.id}`)
              );
            }
          });
      }
    }
  }
}

export function resetShownAlerts(): void {
  shownSosAlerts.clear();
}
