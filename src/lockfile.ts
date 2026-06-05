import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { execFile } from "child_process";
import { Dependency, LockfileType, WorkspaceRoot } from "./types";

const LOCKFILE_NAMES: Record<string, LockfileType> = {
  "package-lock.json": "npm",
  "yarn.lock": "yarn",
  "pnpm-lock.yaml": "pnpm",
};

export function detectWorkspaceRoots(): WorkspaceRoot[] {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) return [];

  const roots: WorkspaceRoot[] = [];
  for (const folder of folders) {
    for (const [filename, type] of Object.entries(LOCKFILE_NAMES)) {
      const lockfilePath = path.join(folder.uri.fsPath, filename);
      if (fs.existsSync(lockfilePath)) {
        roots.push({ uri: folder.uri, lockfileType: type, lockfilePath });
        break;
      }
    }
  }
  return roots;
}

export async function parseDependencyTree(root: WorkspaceRoot): Promise<Dependency[]> {
  const cwd = root.uri.fsPath;
  switch (root.lockfileType) {
    case "npm": return parseNpm(cwd);
    case "yarn": return parseYarn(cwd);
    case "pnpm": return parsePnpm(cwd);
  }
}

function exec(cmd: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { cwd, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && !stdout) {
        reject(new Error(`${cmd} ${args.join(" ")} failed: ${stderr || err.message}`));
        return;
      }
      resolve(stdout);
    });
  });
}

// --- npm ---

interface NpmLsNode {
  version?: string;
  dependencies?: Record<string, NpmLsNode>;
}

async function parseNpm(cwd: string): Promise<Dependency[]> {
  const output = await exec("npm", ["ls", "--json", "--all"], cwd);
  const tree: NpmLsNode = JSON.parse(output);
  return flattenNpmTree(tree.dependencies || {}, [], true);
}

function flattenNpmTree(
  deps: Record<string, NpmLsNode>,
  parentPath: string[],
  isDirect: boolean
): Dependency[] {
  const result: Dependency[] = [];
  for (const [name, node] of Object.entries(deps)) {
    if (!node.version) continue;
    const currentPath = [...parentPath, name];
    result.push({
      name,
      version: node.version,
      isDirect,
      path: currentPath,
      dependencies: flattenNpmTree(node.dependencies || {}, currentPath, false),
    });
  }
  return result;
}

// --- yarn ---

interface YarnListEntry {
  name: string;
  children: YarnListEntry[];
}

async function parseYarn(cwd: string): Promise<Dependency[]> {
  const output = await exec("yarn", ["list", "--json", "--no-progress"], cwd);
  for (const line of output.trim().split("\n")) {
    try {
      const parsed = JSON.parse(line);
      if (parsed.type === "tree" && parsed.data?.trees) {
        return flattenYarnTree(parsed.data.trees, [], true);
      }
    } catch {
      continue;
    }
  }
  return parsePackageJsonFallback(cwd);
}

function flattenYarnTree(
  trees: YarnListEntry[],
  parentPath: string[],
  isDirect: boolean
): Dependency[] {
  const result: Dependency[] = [];
  for (const entry of trees) {
    const atIndex = entry.name.lastIndexOf("@");
    if (atIndex <= 0) continue;
    const name = entry.name.substring(0, atIndex);
    const version = entry.name.substring(atIndex + 1);
    const currentPath = [...parentPath, name];
    result.push({
      name,
      version,
      isDirect,
      path: currentPath,
      dependencies: flattenYarnTree(entry.children || [], currentPath, false),
    });
  }
  return result;
}

// --- pnpm ---

interface PnpmListNode {
  version?: string;
  dependencies?: Record<string, PnpmListNode>;
}

async function parsePnpm(cwd: string): Promise<Dependency[]> {
  const output = await exec("pnpm", ["list", "--json", "--depth", "Infinity"], cwd);
  const parsed = JSON.parse(output);
  const project = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!project) return [];
  return flattenPnpmTree(project.dependencies || {}, [], true);
}

function flattenPnpmTree(
  deps: Record<string, PnpmListNode>,
  parentPath: string[],
  isDirect: boolean
): Dependency[] {
  const result: Dependency[] = [];
  for (const [name, node] of Object.entries(deps)) {
    if (!node.version) continue;
    const currentPath = [...parentPath, name];
    result.push({
      name,
      version: node.version,
      isDirect,
      path: currentPath,
      dependencies: flattenPnpmTree(node.dependencies || {}, currentPath, false),
    });
  }
  return result;
}

// --- fallback ---

async function parsePackageJsonFallback(cwd: string): Promise<Dependency[]> {
  const pkgPath = path.join(cwd, "package.json");
  if (!fs.existsSync(pkgPath)) return [];
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
  return Object.entries(allDeps).map(([name, versionRange]) => ({
    name,
    version: String(versionRange).replace(/^[\^~>=<]*/g, ""),
    isDirect: true,
    path: [name],
    dependencies: [],
  }));
}

export function collectPackageNames(deps: Dependency[]): Set<string> {
  const names = new Set<string>();
  function walk(dep: Dependency) {
    names.add(dep.name);
    for (const child of dep.dependencies) walk(child);
  }
  for (const dep of deps) walk(dep);
  return names;
}
