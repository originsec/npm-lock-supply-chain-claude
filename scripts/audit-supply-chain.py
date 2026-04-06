"""Audit changed package-lock.json dependencies for supply chain attacks.

Downloads old and new npm tarballs from the registry, diffs them locally,
and feeds each diff to Claude for security analysis. Outputs a Markdown
PR comment to stdout.

Usage:
    python3 scripts/audit-supply-chain.py [base-ref]

base-ref defaults to origin/main.
Requires ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_VERSION = "2023-06-01"
USER_AGENT = "npm-lock-supply-chain-audit/1.0 (github.com/originsec/npm-lock-supply-chain-claude)"
DOWNLOAD_DELAY = 0.25  # courtesy delay between npm registry downloads (seconds)
MAX_COMMENT_CHARS = 60_000  # GitHub comment limit is 65536; leave headroom
SUPPRESS_MARKER = "[supply-chain-audit-ok]"
LOCKFILE_NAME = "package-lock.json"

SYSTEM_PROMPT = """\
You are a supply chain security auditor for JavaScript/Node.js packages published on npm. \
You analyze diffs between versions of package dependencies to detect signs of supply \
chain attacks, malicious code injection, or suspicious changes.

Evaluate the diff and produce a JSON verdict with these fields:
- "risk": one of "none", "low", "medium", "high", "critical"
- "summary": a 1-2 sentence summary of your findings
- "findings": an array of objects, each with:
    - "severity": "low", "medium", "high", or "critical"
    - "description": what you found and why it is suspicious
    - "evidence": the relevant code snippet, file path, or pattern

Signals to look for (non-exhaustive):
1. package.json install/preinstall/postinstall scripts that run code at install time \
   (lifecycle hooks in "scripts" field, especially preinstall, install, postinstall, \
   preuninstall, postuninstall)
2. index.js or main entry points that execute code on require() with side effects \
   (network calls, file writes, process spawning, child_process usage)
3. Obfuscated code: base64 decoding, Buffer.from() with encoded strings, XOR operations, \
   hex-encoded strings, String.fromCharCode() chains, eval() of encoded strings, \
   new Function() with constructed code, vm.runInNewContext(), or intentionally \
   confusing variable names
4. Network calls to unfamiliar or suspicious domains, especially in non-networking packages \
   (http.request, https.request, fetch, axios, node-fetch, got, request)
5. File system access outside the package's own directory, especially writes to well-known \
   credential locations (~/.ssh, ~/.aws, ~/.gnupg, ~/.config, ~/.npmrc, browser profile \
   directories, keychain/credential stores, .git/config)
6. New unexpected dependencies added in package.json (dependency injection / dependency confusion)
7. Binary blobs, .node/.dll/.so files, WebAssembly (.wasm), encoded payloads, or large \
   opaque data literals
8. Environment variable reading for sensitive values (API keys, tokens, credentials, \
   SSH keys, npm tokens via process.env)
9. Use of child_process (exec, execSync, spawn, spawnSync, execFile, fork) to execute \
   shell commands, especially with dynamically constructed command strings
10. Changes that look like dependency confusion (name squatting, typosquatting, scope confusion)
11. Conditional logic that behaves differently in CI environments vs local builds \
    (checking CI, GITHUB_ACTIONS, TRAVIS, JENKINS, etc. via process.env)
12. Code that collects and exfiltrates system information (os.hostname(), os.userInfo(), \
    os.networkInterfaces(), process.env dump, installed packages list)
13. Lifecycle scripts (preinstall/postinstall) that execute unexpected code, \
    especially downloading and executing remote scripts
14. Significant functionality changes that don't match the package's stated purpose \
    (e.g., a JSON parser suddenly including HTTP client code)
15. Removal or weakening of security checks, cryptographic operations, or input validation
16. Native addon loading (require('bindings'), node-gyp builds, N-API/.node files, \
    dlopen usage)
17. Monkey-patching of Node.js built-in modules (e.g., overriding http, https, net, \
    tls, dns, fs modules via prototype pollution or direct replacement)
18. Data exfiltration via DNS, HTTP POST to external servers, or writing to /tmp for pickup
19. Prototype pollution attacks (Object.assign to Object.prototype, __proto__ manipulation, \
    constructor.prototype modifications)
20. Webpack/bundler config modifications that inject code at build time

For "none" risk: the changes look routine (version bumps, docs, bug fixes, new features \
consistent with the package's purpose).
For "low" risk: minor concerns worth noting but likely benign.
For "medium" risk: unusual patterns that warrant manual review.
For "high" risk: strong indicators of potentially malicious behavior.
For "critical" risk: clear evidence of malicious code or supply chain attack techniques.

Respond ONLY with the JSON object. No markdown fences, no commentary.\
"""

# ---------------------------------------------------------------------------
# package-lock.json parsing
# ---------------------------------------------------------------------------


def parse_lockfile(text: str) -> dict[str, dict[str, str | None]]:
    """Parse a package-lock.json into {name: {version: resolved_url}} for registry packages.

    Supports lockfileVersion 2 and 3 (the flat ``packages`` map). Only includes
    packages sourced from the npm registry (skips local/file/git dependencies).
    """
    if not text.strip():
        return {}

    data = json.loads(text)
    packages: dict[str, dict[str, str | None]] = {}
    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version >= 2:
        # lockfileVersion 2 and 3 use the flat "packages" map
        for pkg_path, info in data.get("packages", {}).items():
            # Skip the root project entry (empty string key)
            if not pkg_path:
                continue

            version = info.get("version")
            if not version:
                continue

            # Derive the package name from the path
            # e.g. "node_modules/@babel/parser" -> "@babel/parser"
            # e.g. "node_modules/lodash" -> "lodash"
            # e.g. "node_modules/foo/node_modules/bar" -> "bar" (nested)
            name = _extract_package_name(pkg_path)
            if not name:
                continue

            resolved = info.get("resolved", "")

            # Skip non-registry deps (file:, git+, github:, link:, etc.)
            if not resolved or _is_non_registry_url(resolved):
                continue

            # Use the resolved URL for downloading the tarball
            packages.setdefault(name, {})[version] = resolved

    else:
        # lockfileVersion 1 uses the nested "dependencies" tree
        _parse_v1_dependencies(data.get("dependencies", {}), packages)

    return packages


def _extract_package_name(pkg_path: str) -> str | None:
    """Extract the npm package name from a node_modules path.

    Examples:
        "node_modules/lodash" -> "lodash"
        "node_modules/@babel/parser" -> "@babel/parser"
        "node_modules/foo/node_modules/bar" -> "bar"
        "node_modules/@scope/pkg/node_modules/@other/dep" -> "@other/dep"
    """
    # Find the last "node_modules/" segment and take what follows
    prefix = "node_modules/"
    idx = pkg_path.rfind(prefix)
    if idx == -1:
        return None
    name_part = pkg_path[idx + len(prefix):]
    if not name_part:
        return None
    return name_part


def _is_non_registry_url(resolved: str) -> bool:
    """Return True if the resolved URL points to a non-registry source."""
    non_registry_prefixes = ("file:", "git+", "git:", "github:", "link:")
    return any(resolved.startswith(p) for p in non_registry_prefixes)


def _parse_v1_dependencies(
    deps: dict, packages: dict[str, dict[str, str | None]]
) -> None:
    """Recursively parse lockfileVersion 1 nested dependencies."""
    for name, info in deps.items():
        version = info.get("version", "")
        resolved = info.get("resolved", "")

        if version and resolved and not _is_non_registry_url(resolved):
            packages.setdefault(name, {})[version] = resolved

        # Recurse into nested dependencies
        nested = info.get("dependencies")
        if nested:
            _parse_v1_dependencies(nested, packages)


def parse_version(v: str) -> tuple[int, ...]:
    """Parse a semver version string into a comparable tuple.

    Handles versions like 1.2.3, 1.2.3-beta.1, etc. by extracting
    only the numeric segments for comparison.
    """
    match = re.match(r"(\d+(?:\.\d+)*)", v)
    if not match:
        return (0,)
    return tuple(int(x) for x in match.group(1).split("."))


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


@dataclass
class Change:
    name: str
    old_version: str | None
    new_version: str | None
    change_type: str  # "added", "upgraded", "downgraded"
    old_resolved_url: str | None = None
    new_resolved_url: str | None = None


def compute_changes(
    base_pkgs: dict[str, dict[str, str | None]],
    head_pkgs: dict[str, dict[str, str | None]],
) -> list[Change]:
    """Compute the list of dependency changes between base and head."""
    changes: list[Change] = []
    all_names = set(base_pkgs) | set(head_pkgs)

    for name in sorted(all_names):
        base_versions = set(base_pkgs.get(name, {}).keys())
        head_versions = set(head_pkgs.get(name, {}).keys())

        if base_versions == head_versions:
            continue

        # Skip removed deps entirely -- no supply chain risk
        if name not in head_pkgs:
            continue

        removed = base_versions - head_versions
        added = head_versions - base_versions

        if name not in base_pkgs:
            # Entirely new dependency
            for ver in sorted(added, key=parse_version):
                resolved_url = head_pkgs[name].get(ver)
                changes.append(Change(name, None, ver, "added", None, resolved_url))
        else:
            # Version changed -- pair up removed/added versions
            removed_sorted = sorted(removed, key=parse_version)
            added_sorted = sorted(added, key=parse_version)

            if len(removed_sorted) == 1 and len(added_sorted) == 1:
                old_v = removed_sorted[0]
                new_v = added_sorted[0]
                change_type = (
                    "downgraded"
                    if parse_version(new_v) < parse_version(old_v)
                    else "upgraded"
                )
                old_url = base_pkgs[name].get(old_v)
                new_url = head_pkgs[name].get(new_v)
                changes.append(Change(name, old_v, new_v, change_type, old_url, new_url))
            else:
                # Multiple version changes -- pair by position, extras are adds
                added_sorted_copy = list(added_sorted)
                for old_v in removed_sorted:
                    if added_sorted_copy:
                        new_v = added_sorted_copy.pop(0)
                        change_type = (
                            "downgraded"
                            if parse_version(new_v) < parse_version(old_v)
                            else "upgraded"
                        )
                        old_url = base_pkgs[name].get(old_v)
                        new_url = head_pkgs[name].get(new_v)
                        changes.append(Change(name, old_v, new_v, change_type, old_url, new_url))
                for new_v in added_sorted_copy:
                    new_url = head_pkgs[name].get(new_v)
                    changes.append(Change(name, None, new_v, "added", None, new_url))

    return changes


# ---------------------------------------------------------------------------
# Package downloading and extraction
# ---------------------------------------------------------------------------


def download_tarball(
    name: str, version: str, resolved_url: str | None, dest_dir: Path
) -> Path | None:
    """Download an npm tarball. Returns path or None on failure.

    If resolved_url is provided (from the lockfile), use it directly.
    Otherwise, fall back to the npm registry API to find the tarball URL.
    """
    if not resolved_url:
        # Fall back to npm registry API
        api_url = f"https://registry.npmjs.org/{name}/{version}"
        req = urllib.request.Request(api_url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            resolved_url = data.get("dist", {}).get("tarball")
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as e:
            print(f"::warning::Failed to query npm registry for {name}@{version}: {e}", file=sys.stderr)
            return None

    if not resolved_url:
        print(f"::warning::No tarball found for {name}@{version}", file=sys.stderr)
        return None

    # Determine filename from URL
    filename = resolved_url.rsplit("/", 1)[-1]
    # npm tarballs may have URL-encoded names; sanitize
    filename = filename.split("?")[0]
    dest = dest_dir / filename
    req = urllib.request.Request(resolved_url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return dest
    except (urllib.error.URLError, OSError) as e:
        print(f"::warning::Failed to download {name}@{version}: {e}", file=sys.stderr)
        return None


def extract_tarball(archive: Path, dest_dir: Path) -> Path | None:
    """Extract an npm tarball (.tgz). Returns the extracted directory path.

    npm tarballs are gzipped tar archives that extract to a ``package/`` directory.
    """
    try:
        if archive.name.endswith((".tgz", ".tar.gz")):
            with tarfile.open(archive, "r:gz") as tf:
                if hasattr(tarfile, "data_filter"):
                    tf.extractall(dest_dir, filter="data")
                else:
                    for member in tf.getmembers():
                        resolved = (dest_dir / member.name).resolve()
                        if not str(resolved).startswith(str(dest_dir.resolve())):
                            print(
                                f"::warning::Path traversal in {archive.name}: {member.name}",
                                file=sys.stderr,
                            )
                            return None
                    tf.extractall(dest_dir)
        else:
            print(f"::warning::Unknown archive format: {archive.name}", file=sys.stderr)
            return None

        # npm tarballs typically extract to a "package/" directory
        dirs = [item for item in dest_dir.iterdir() if item.is_dir()]
        if len(dirs) == 1:
            return dirs[0]
        # If multiple dirs or no dirs, use dest_dir itself
        return dest_dir if any(dest_dir.iterdir()) else None
    except (tarfile.TarError, OSError) as e:
        print(f"::warning::Failed to extract {archive.name}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def is_binary(path: Path) -> bool:
    """Heuristic: file is binary if first 8KB contains null bytes."""
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def collect_files(directory: Path) -> dict[str, Path]:
    """Collect all files in a directory as {relative_path: absolute_path}."""
    files = {}
    if directory is None:
        return files
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(directory)).replace("\\", "/")
            files[rel] = path
    return files


def diff_packages(old_dir: Path | None, new_dir: Path) -> str:
    """Produce a unified diff between two extracted package directories."""
    old_files = collect_files(old_dir) if old_dir else {}
    new_files = collect_files(new_dir)

    all_paths = sorted(set(old_files) | set(new_files))
    diff_parts: list[str] = []

    for rel_path in all_paths:
        old_path = old_files.get(rel_path)
        new_path = new_files.get(rel_path)

        if old_path and new_path:
            if is_binary(old_path) or is_binary(new_path):
                old_size = old_path.stat().st_size
                new_size = new_path.stat().st_size
                if old_size != new_size:
                    diff_parts.append(
                        f"Binary file {rel_path} changed ({old_size} -> {new_size} bytes)\n"
                    )
                continue
            try:
                old_lines = old_path.read_text(errors="replace").splitlines(keepends=True)
                new_lines = new_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                old_lines, new_lines, fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}"
            )
            diff_text = "".join(diff)
            if diff_text:
                diff_parts.append(diff_text)

        elif new_path:
            if is_binary(new_path):
                size = new_path.stat().st_size
                diff_parts.append(f"Binary file {rel_path} added ({size} bytes)\n")
                continue
            try:
                lines = new_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                [], lines, fromfile="/dev/null", tofile=f"b/{rel_path}"
            )
            diff_parts.append("".join(diff))

        elif old_path:
            if is_binary(old_path):
                size = old_path.stat().st_size
                diff_parts.append(f"Binary file {rel_path} removed ({size} bytes)\n")
                continue
            try:
                lines = old_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                lines, [], fromfile=f"a/{rel_path}", tofile="/dev/null"
            )
            diff_parts.append("".join(diff))

    return "\n".join(diff_parts)


# ---------------------------------------------------------------------------
# Claude API
# ---------------------------------------------------------------------------


def call_claude(
    name: str,
    old_version: str | None,
    new_version: str,
    change_type: str,
    diff_text: str,
    api_key: str,
    model: str,
) -> dict:
    """Call Claude to audit a package diff. Returns the parsed verdict dict."""
    if change_type == "added":
        user_msg = (
            f'Analyze the following contents for the newly added npm package dependency "{name}" '
            f"version {new_version}.\n\n"
            f"This is a new dependency being added to the project. All file contents are shown "
            f"as additions. Pay special attention to whether this package's purpose matches its "
            f"stated description and whether it contains any suspicious functionality.\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )
    else:
        user_msg = (
            f'Analyze the following diff for the npm package "{name}" '
            f"({change_type} from {old_version} to {new_version}).\n\n"
            f"The diff shows all file changes between the old and new versions of this package "
            f"as published on the npm registry.\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )

    body = json.dumps(
        {
            "model": model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "Anthropic-Version": ANTHROPIC_API_VERSION,
        "User-Agent": USER_AGENT,
    }

    req = urllib.request.Request(CLAUDE_API_URL, data=body, headers=headers, method="POST")

    last_err = None
    for attempt in range(2):
        if attempt > 0:
            time.sleep(5)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
            text = ""
            for block in result.get("content", []):
                if block.get("type") == "text":
                    text += block["text"]
            # Strip markdown fences if Claude included them despite instructions
            text = text.strip()
            if text.startswith("```"):
                text = re.sub(r"^```\w*\n?", "", text)
                text = re.sub(r"\n?```$", "", text)
                text = text.strip()
            return json.loads(text)
        except json.JSONDecodeError as e:
            last_err = f"Invalid JSON from Claude: {e}\nRaw response: {text[:500]}"
        except (urllib.error.URLError, OSError) as e:
            last_err = f"API request failed: {e}"

    # All retries exhausted
    return {
        "risk": "high",
        "summary": f"Audit failed -- manual review required. Error: {last_err}",
        "findings": [],
    }


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

RISK_EMOJI = {
    "none": "\u2705",
    "low": "\u2705",
    "medium": "\u26a0\ufe0f",
    "high": "\U0001f534",
    "critical": "\U0001f534",
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


@dataclass
class Verdict:
    change: Change
    risk: str
    summary: str
    findings: list[dict]
    error: str | None = None


def format_comment(verdicts: list[Verdict]) -> str:
    """Format all verdicts into a single Markdown PR comment."""
    verdicts.sort(key=lambda v: RISK_ORDER.get(v.risk, 5))

    high_risk_count = sum(1 for v in verdicts if v.risk in ("high", "critical"))
    total = len(verdicts)

    lines: list[str] = []
    lines.append("## Supply Chain Audit\n")

    if high_risk_count > 0:
        lines.append(
            f"> **{high_risk_count}** of **{total}** dependency changes flagged "
            f"as high/critical risk.\n"
        )
    else:
        lines.append(
            f"> Analyzed **{total}** dependency changes. No high-risk findings.\n"
        )

    for v in verdicts:
        emoji = RISK_EMOJI.get(v.risk, "\u2753")
        change = v.change
        if change.old_version:
            version_str = f"`{change.old_version}` \u2192 `{change.new_version}`"
        else:
            version_str = f"`{change.new_version}` (new)"

        header = f"{emoji} **`{change.name}`** {version_str} \u2014 **{v.risk}**"

        if v.risk in ("high", "critical"):
            lines.append(f"### {header}\n")
            lines.append(f"{v.summary}\n")
            if v.findings:
                for f in v.findings:
                    sev = f.get("severity", "?")
                    desc = f.get("description", "")
                    evidence = f.get("evidence", "")
                    lines.append(f"- **[{sev}]** {desc}")
                    if evidence:
                        lines.append(f"  ```\n  {evidence}\n  ```")
                lines.append("")
        else:
            lines.append(f"<details>\n<summary>{header}</summary>\n")
            lines.append(f"{v.summary}\n")
            if v.findings:
                for f in v.findings:
                    sev = f.get("severity", "?")
                    desc = f.get("description", "")
                    evidence = f.get("evidence", "")
                    lines.append(f"- **[{sev}]** {desc}")
                    if evidence:
                        lines.append(f"  ```\n  {evidence}\n  ```")
            lines.append("\n</details>\n")

    lines.append("---")
    lines.append(
        f"*Audit performed by Claude (`{os.environ.get('AUDIT_MODEL', DEFAULT_MODEL)}`) "
        f"via [npm-lock-supply-chain-claude]"
        f"(https://github.com/originsec/npm-lock-supply-chain-claude)*"
    )

    comment = "\n".join(lines)

    if len(comment) > MAX_COMMENT_CHARS:
        truncation_note = (
            "\n\n> **Note:** This comment was truncated due to GitHub's size limit. "
            "See CI logs for the full audit output.\n"
        )
        comment = comment[: MAX_COMMENT_CHARS - len(truncation_note)] + truncation_note

    return comment


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    base_ref = sys.argv[1] if len(sys.argv) > 1 else "origin/main"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("::error::ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    model = os.environ.get("AUDIT_MODEL", DEFAULT_MODEL)

    # Check for suppression marker in PR body
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            with open(event_path) as f:
                event = json.load(f)
            pr_body = event.get("pull_request", {}).get("body") or ""
            if SUPPRESS_MARKER in pr_body:
                print(
                    f"Supply chain audit suppressed via '{SUPPRESS_MARKER}' in PR body.",
                    file=sys.stderr,
                )
                return 0
        except (OSError, json.JSONDecodeError):
            pass

    # Read base and head package-lock.json
    try:
        base_text = subprocess.check_output(
            ["git", "show", f"{base_ref}:{LOCKFILE_NAME}"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError:
        print(f"::warning::Could not read {LOCKFILE_NAME} from {base_ref}, treating all deps as new.",
              file=sys.stderr)
        base_text = ""

    try:
        with open(LOCKFILE_NAME) as f:
            head_text = f.read()
    except OSError as e:
        print(f"::error::Could not read {LOCKFILE_NAME}: {e}", file=sys.stderr)
        return 1

    base_pkgs = parse_lockfile(base_text)
    head_pkgs = parse_lockfile(head_text)
    changes = compute_changes(base_pkgs, head_pkgs)

    if not changes:
        print("No registry dependency changes detected.", file=sys.stderr)
        return 0

    print(
        f"Found {len(changes)} dependency change(s) to audit.",
        file=sys.stderr,
    )

    verdicts: list[Verdict] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        for i, change in enumerate(changes):
            print(
                f"[{i+1}/{len(changes)}] Auditing {change.name} "
                f"({change.old_version} -> {change.new_version})...",
                file=sys.stderr,
            )

            # Download and extract new version
            new_archive = download_tarball(
                change.name, change.new_version, change.new_resolved_url, tmp
            )
            if not new_archive:
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="high",
                        summary=f"Could not download {change.name}@{change.new_version} tarball "
                        f"from npm. Manual review required.",
                        findings=[],
                        error="download_failed",
                    )
                )
                continue

            new_extract_dir = tmp / f"new-{change.name}-{change.new_version}"
            new_extract_dir.mkdir(parents=True)
            new_dir = extract_tarball(new_archive, new_extract_dir)
            if not new_dir:
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="high",
                        summary=f"Could not extract {change.name}@{change.new_version} tarball. "
                        f"Manual review required.",
                        findings=[],
                        error="extract_failed",
                    )
                )
                continue

            # Download and extract old version (if upgrading/downgrading)
            old_dir = None
            if change.old_version:
                if DOWNLOAD_DELAY > 0:
                    time.sleep(DOWNLOAD_DELAY)
                old_archive = download_tarball(
                    change.name, change.old_version, change.old_resolved_url, tmp
                )
                if old_archive:
                    old_extract_dir = tmp / f"old-{change.name}-{change.old_version}"
                    old_extract_dir.mkdir(parents=True)
                    old_dir = extract_tarball(old_archive, old_extract_dir)

            if DOWNLOAD_DELAY > 0:
                time.sleep(DOWNLOAD_DELAY)

            # Diff
            diff_text = diff_packages(old_dir, new_dir)
            if not diff_text.strip():
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="none",
                        summary="No source changes detected between versions.",
                        findings=[],
                    )
                )
                continue

            # Call Claude
            verdict_data = call_claude(
                name=change.name,
                old_version=change.old_version,
                new_version=change.new_version,
                change_type=change.change_type,
                diff_text=diff_text,
                api_key=api_key,
                model=model,
            )

            verdicts.append(
                Verdict(
                    change=change,
                    risk=verdict_data.get("risk", "medium"),
                    summary=verdict_data.get("summary", "No summary provided."),
                    findings=verdict_data.get("findings", []),
                )
            )

    # Format and output the comment
    comment = format_comment(verdicts)
    print(comment)

    # Exit with non-zero if any critical findings
    has_critical = any(v.risk == "critical" for v in verdicts)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
