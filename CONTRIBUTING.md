# Contributing

Thanks for your interest in Trust Me Bro. Here's how to get started.

## Setup

```bash
git clone https://github.com/uskhokhar/trust-me-bro.git
cd trust-me-bro
npm install
npm run compile
```

Press **F5** in VS Code to launch the Extension Development Host.

## Development workflow

1. Make changes in `src/`
2. `npm run watch` for continuous compilation
3. **F5** to test in the Extension Development Host
4. Check the **Output** panel (select "Trust Me Bro") for logs

## Testing with vulnerable packages

Create a throwaway project to test against real advisories:

```bash
mkdir /tmp/tmb-test && cd /tmp/tmb-test
echo '{"name":"tmb-test","private":true,"dependencies":{"lodash":"4.17.20","axios":"0.21.0","minimist":"0.2.1"}}' > package.json
npm install --ignore-scripts
```

Open this folder in the Extension Development Host.

## Pull requests

- Open an issue first for non-trivial changes
- One concern per PR
- Make sure `npm run compile` passes with no errors
- Test with at least one known-vulnerable package

## Code style

- No verbose comments — the code should speak for itself
- Comments explain *why*, not *what*
- Keep functions short; extract when logic is non-obvious
- No unnecessary abstractions

## Reporting security issues

If you find a security vulnerability in the extension itself, please email me directly at `contact.uskhokhar@gmail.com` instead of opening a public issue.
