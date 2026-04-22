# npm-lock-supply-chain-claude

A GitHub Action that audits package-lock.json dependency changes for supply chain attacks using Claude.

When a PR modifies any `package-lock.json` (root or nested, e.g. `frontend/package-lock.json`), this action:

1. Diffs the lockfile to find every added, upgraded, or downgraded registry dependency
2. Downloads the old and new tarballs from the npm registry (URLs are embedded in package-lock.json)
3. Extracts and diffs the actual source code between versions
4. Sends each diff to Claude for security analysis
5. Posts a single PR comment with per-dependency risk verdicts

## What it detects

- `package.json` lifecycle scripts that run code at install time (preinstall, postinstall, install hooks)
- Entry points that execute code on `require()` (network calls, file writes, child_process usage)
- Obfuscated code (base64/Buffer.from decoding, eval/new Function of encoded strings, String.fromCharCode chains)
- Network calls to suspicious domains in non-networking packages
- File system writes to credential locations (~/.ssh, ~/.aws, ~/.npmrc, browser profiles)
- Unexpected new dependencies injected in package.json (dependency confusion)
- Binary blobs, .node/.so/.dll files, WebAssembly, or encoded payloads
- Environment variable harvesting for secrets/tokens via process.env
- child_process (exec, spawn, execFile) usage for shell execution
- CI-conditional behavior (code that runs differently in CI vs local)
- Native addon loading (node-gyp, N-API, bindings, dlopen)
- Monkey-patching of Node.js built-in modules (http, https, net, fs)
- Prototype pollution attacks (__proto__, constructor.prototype)
- Data exfiltration via DNS, HTTP POST, or temp files
- Webpack/bundler config modifications that inject code at build time

## Usage

Add this workflow to your repository at `.github/workflows/supply-chain-audit.yml`:

```yaml
name: Supply Chain Audit

on:
  pull_request:
    paths:
      - "**/package-lock.json"

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    name: Audit dependency changes
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: originsec/npm-lock-supply-chain-claude@main
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic_api_key` | Yes | - | Anthropic API key for Claude |
| `model` | No | `claude-sonnet-4-20250514` | Claude model to use |
| `base_ref` | No | Auto-detected from PR | Git ref to diff against |

### Secrets

Add `ANTHROPIC_API_KEY` to your repository secrets (Settings > Secrets and variables > Actions).

## How it works

package-lock.json (lockfileVersion 2 and 3) embeds direct tarball URLs from the npm registry
for each dependency in the `resolved` field. The script uses these URLs to download the exact
archives, extracts them, and performs a local file-by-file diff using Python's `difflib`.

For lockfileVersion 1, it falls back to querying the npm registry API for tarball URLs.

The diff is then sent to Claude with a system prompt tuned for JavaScript/Node.js-specific
supply chain attack indicators, based on real-world attacks like the
[event-stream incident](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident),
[ua-parser-js hijack](https://github.com/nicedayfor/Advisories/blob/main/npm-ua-parser-js-compromise.md),
and [colors/faker sabotage](https://snyk.io/blog/open-source-npm-packages-colors-702faker/).

## Suppression

Add `[supply-chain-audit-ok]` to your PR description to skip the audit for a specific PR.

## Requirements

- Python 3.11+ (available on `ubuntu-latest` runners)
- `fetch-depth: 0` on checkout (needed to diff against the base branch)

## License

Prelude Research License -- see [LICENSE](LICENSE) for details.
