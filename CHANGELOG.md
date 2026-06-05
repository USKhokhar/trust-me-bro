# Changelog

All notable changes to Trust Me Bro will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-05

First public release.

### Features

- Continuous dependency monitoring via lockfile watching and periodic advisory polling
- Directional safety alerts: SOS, Don't Upgrade, Don't Downgrade
- Advisory data from OSV.dev (includes GitHub Advisory Database)
- Sidebar panel with dependency tree and alert details
- Status bar with ambient trust summary
- Toast notifications for critical SOS alerts
- Support for `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`
- Multi-root workspace support
- Offline resilience with disk-persisted advisory cache
- Configurable poll interval (default: 30 minutes)
- Force Refresh command to clear cache and re-scan
