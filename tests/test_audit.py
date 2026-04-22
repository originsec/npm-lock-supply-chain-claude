"""Unit tests for audit-supply-chain.py."""

from __future__ import annotations

import importlib
import json
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

# Add scripts/ to path so we can import the module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

audit = importlib.import_module("audit-supply-chain")

parse_lockfile = audit.parse_lockfile
parse_version = audit.parse_version
compute_changes = audit.compute_changes
Change = audit.Change
Verdict = audit.Verdict
is_binary = audit.is_binary
collect_files = audit.collect_files
diff_packages = audit.diff_packages
format_comment = audit.format_comment
extract_tarball = audit.extract_tarball
_extract_package_name = audit._extract_package_name
_is_non_registry_url = audit._is_non_registry_url
LOCKFILE_RE = audit.LOCKFILE_RE
cache_key = audit.cache_key
load_verdict_cache = audit.load_verdict_cache
save_verdict_cache = audit.save_verdict_cache
CACHE_VERSION = audit.CACHE_VERSION
parse_verdict_text = audit.parse_verdict_text


# ---------------------------------------------------------------------------
# Verdict cache
# ---------------------------------------------------------------------------


class TestCacheKey:
    def test_includes_all_identifiers(self):
        assert (
            cache_key("lodash", "https://reg/a.tgz", "https://reg/b.tgz")
            == "lodash|https://reg/a.tgz|https://reg/b.tgz"
        )

    def test_none_old_id_encodes_as_empty(self):
        assert cache_key("lodash", None, "https://reg/b.tgz") == "lodash||https://reg/b.tgz"


class TestVerdictCache:
    def test_returns_empty_when_path_none(self):
        assert load_verdict_cache(None) == {}

    def test_malformed_json_returns_empty(self, tmp_path):
        p = tmp_path / "cache.json"
        p.write_text("{not json")
        assert load_verdict_cache(str(p)) == {}

    def test_wrong_version_returns_empty(self, tmp_path):
        p = tmp_path / "cache.json"
        p.write_text(json.dumps({"version": 999, "entries": {"k": {"risk": "none"}}}))
        assert load_verdict_cache(str(p)) == {}

    def test_roundtrip(self, tmp_path):
        p = str(tmp_path / "cache.json")
        entries = {"lodash|a|b": {"risk": "none", "summary": "OK", "findings": []}}
        save_verdict_cache(p, entries)
        assert load_verdict_cache(p) == entries

    def test_save_no_path_is_noop(self):
        save_verdict_cache(None, {"x": {"risk": "none"}})


# ---------------------------------------------------------------------------
# LOCKFILE_RE (nested package-lock.json discovery)
# ---------------------------------------------------------------------------


class TestLockfileRegex:
    def test_matches_root(self):
        assert LOCKFILE_RE.search("package-lock.json")

    def test_matches_nested(self):
        assert LOCKFILE_RE.search("frontend/package-lock.json")

    def test_matches_deeply_nested(self):
        assert LOCKFILE_RE.search("apps/web/client/package-lock.json")

    def test_rejects_package_json(self):
        assert not LOCKFILE_RE.search("package.json")
        assert not LOCKFILE_RE.search("frontend/package.json")

    def test_rejects_yarn_lock(self):
        assert not LOCKFILE_RE.search("yarn.lock")
        assert not LOCKFILE_RE.search("frontend/pnpm-lock.yaml")

    def test_rejects_similar_suffix(self):
        assert not LOCKFILE_RE.search("package-lock.json.bak")
        assert not LOCKFILE_RE.search("my-package-lock.json.txt")


# ---------------------------------------------------------------------------
# Claude response parsing — tolerates trailing commentary after JSON
# ---------------------------------------------------------------------------


class TestClaudeResponseParsing:
    """Exercises parse_verdict_text, the verdict extractor call_claude uses."""

    def test_plain_json(self):
        raw = '{"risk": "none", "summary": "OK", "findings": []}'
        assert parse_verdict_text(raw)["risk"] == "none"

    def test_json_with_trailing_commentary(self):
        raw = (
            '{"risk": "none", "summary": "Routine.", "findings": []}\n\n'
            "The diff shows a standard version increment with no concerns."
        )
        result = parse_verdict_text(raw)
        assert result["risk"] == "none"
        assert result["summary"] == "Routine."

    def test_fenced_json_with_trailing_commentary(self):
        raw = (
            '```json\n{"risk": "low", "summary": "Minor.", "findings": []}\n```\n'
            "Additional notes from the model."
        )
        assert parse_verdict_text(raw)["risk"] == "low"

    def test_strips_markdown_fences(self):
        raw = '```json\n{"risk": "none", "summary": "OK", "findings": []}\n```'
        assert parse_verdict_text(raw)["risk"] == "none"

    def test_json_with_leading_prose(self):
        # Observed in production (cargo-lock audit): Claude prefixes the JSON
        # with a sentence describing what it's about to do, then emits the object.
        raw = (
            "Looking at the diff for the newly added package, I'll analyze "
            "the key components:\n\n"
            '{"risk": "low", "summary": "Routine package.", "findings": []}'
        )
        result = parse_verdict_text(raw)
        assert result["risk"] == "low"
        assert result["summary"] == "Routine package."

    def test_json_with_leading_and_trailing_prose(self):
        raw = (
            "Here is the verdict:\n\n"
            '{"risk": "medium", "summary": "Unusual.", "findings": []}\n\n'
            "Let me know if you want me to dig deeper."
        )
        assert parse_verdict_text(raw)["risk"] == "medium"

    def test_leading_prose_contains_stray_brace(self):
        # A `{` inside the leading prose must not derail extraction — the
        # extractor has to walk past non-parseable starts.
        raw = (
            "I noticed a snippet like `function foo() { ... }` in the install "
            "script, but the overall verdict is:\n\n"
            '{"risk": "low", "summary": "Benign.", "findings": []}'
        )
        assert parse_verdict_text(raw)["risk"] == "low"

    def test_no_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            parse_verdict_text("no json here, just prose")


# ---------------------------------------------------------------------------
# _extract_package_name
# ---------------------------------------------------------------------------


class TestExtractPackageName:
    def test_simple_package(self):
        assert _extract_package_name("node_modules/lodash") == "lodash"

    def test_scoped_package(self):
        assert _extract_package_name("node_modules/@babel/parser") == "@babel/parser"

    def test_nested_package(self):
        assert _extract_package_name("node_modules/foo/node_modules/bar") == "bar"

    def test_nested_scoped_package(self):
        assert _extract_package_name("node_modules/@scope/pkg/node_modules/@other/dep") == "@other/dep"

    def test_no_node_modules(self):
        assert _extract_package_name("src/lib/lodash") is None

    def test_empty_after_prefix(self):
        assert _extract_package_name("node_modules/") is None


# ---------------------------------------------------------------------------
# _is_non_registry_url
# ---------------------------------------------------------------------------


class TestIsNonRegistryUrl:
    def test_registry_url(self):
        assert _is_non_registry_url("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz") is False

    def test_file_url(self):
        assert _is_non_registry_url("file:../my-local-pkg") is True

    def test_git_url(self):
        assert _is_non_registry_url("git+https://github.com/example/repo.git") is True

    def test_github_url(self):
        assert _is_non_registry_url("github:user/repo") is True

    def test_link_url(self):
        assert _is_non_registry_url("link:../my-linked-pkg") is True


# ---------------------------------------------------------------------------
# parse_lockfile
# ---------------------------------------------------------------------------


class TestParseLockfile:
    def test_empty_string(self):
        assert parse_lockfile("") == {}

    def test_whitespace_only(self):
        assert parse_lockfile("   \n\n  ") == {}

    def test_single_registry_package_v3(self):
        lockfile = json.dumps({
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc123",
                    "license": "MIT",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "lodash" in result
        assert "4.17.21" in result["lodash"]
        assert result["lodash"]["4.17.21"].startswith("https://")

    def test_scoped_package(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/@babel/core": {
                    "version": "7.24.0",
                    "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
                    "integrity": "sha512-xyz",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "@babel/core" in result
        assert "7.24.0" in result["@babel/core"]

    def test_skips_root_entry(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "my-app" not in result
        assert "lodash" in result

    def test_skips_file_dependencies(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/my-local": {
                    "version": "0.1.0",
                    "resolved": "file:../my-local",
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "my-local" not in result
        assert "lodash" in result

    def test_skips_git_dependencies(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/git-dep": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/example/repo.git#abc123",
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "git-dep" not in result
        assert "lodash" in result

    def test_skips_packages_without_resolved(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/no-resolved": {
                    "version": "1.0.0",
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "no-resolved" not in result
        assert "lodash" in result

    def test_multiple_packages(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-aaa",
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-bbb",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert len(result) == 2
        assert "lodash" in result
        assert "express" in result

    def test_nested_dependency(self):
        lockfile = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/semver": {
                    "version": "7.6.0",
                    "resolved": "https://registry.npmjs.org/semver/-/semver-7.6.0.tgz",
                    "integrity": "sha512-aaa",
                },
                "node_modules/@babel/core/node_modules/semver": {
                    "version": "6.3.1",
                    "resolved": "https://registry.npmjs.org/semver/-/semver-6.3.1.tgz",
                    "integrity": "sha512-bbb",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "semver" in result
        # Both versions should be captured
        assert "7.6.0" in result["semver"]
        assert "6.3.1" in result["semver"]

    def test_lockfile_v1(self):
        lockfile = json.dumps({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "lodash" in result
        assert "4.17.21" in result["lodash"]

    def test_lockfile_v1_nested_deps(self):
        lockfile = json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "foo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                    "integrity": "sha512-aaa",
                    "dependencies": {
                        "bar": {
                            "version": "2.0.0",
                            "resolved": "https://registry.npmjs.org/bar/-/bar-2.0.0.tgz",
                            "integrity": "sha512-bbb",
                        },
                    },
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "foo" in result
        assert "bar" in result

    def test_real_lockfile_structure(self):
        """Test against a realistic package-lock.json v3 structure."""
        lockfile = json.dumps({
            "name": "temp-next-app",
            "version": "0.1.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "temp-next-app",
                    "version": "0.1.0",
                    "dependencies": {"next": "15.3.1", "react": "^19.0.0"},
                    "devDependencies": {"typescript": "^5"},
                },
                "node_modules/next": {
                    "version": "15.3.1",
                    "resolved": "https://registry.npmjs.org/next/-/next-15.3.1.tgz",
                    "integrity": "sha512-abc",
                    "license": "MIT",
                    "dependencies": {"@next/env": "15.3.1"},
                },
                "node_modules/react": {
                    "version": "19.0.0",
                    "resolved": "https://registry.npmjs.org/react/-/react-19.0.0.tgz",
                    "integrity": "sha512-xyz",
                    "license": "MIT",
                },
                "node_modules/typescript": {
                    "version": "5.7.3",
                    "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.7.3.tgz",
                    "integrity": "sha512-def",
                    "dev": True,
                    "license": "Apache-2.0",
                },
            },
        })
        result = parse_lockfile(lockfile)
        assert "next" in result
        assert "react" in result
        assert "typescript" in result
        assert "temp-next-app" not in result


# ---------------------------------------------------------------------------
# parse_version
# ---------------------------------------------------------------------------


class TestParseVersion:
    def test_normal_version(self):
        assert parse_version("1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert parse_version("1.2") == (1, 2)

    def test_four_part_version(self):
        assert parse_version("1.2.3.4") == (1, 2, 3, 4)

    def test_zero_version(self):
        assert parse_version("0.0.0") == (0, 0, 0)

    def test_prerelease_suffix_ignored(self):
        assert parse_version("1.2.3-beta.1") == (1, 2, 3)

    def test_build_metadata(self):
        assert parse_version("1.2.3+build.123") == (1, 2, 3)

    def test_invalid_version(self):
        assert parse_version("not-a-version") == (0,)

    def test_ordering(self):
        assert parse_version("1.0.0") < parse_version("2.0.0")
        assert parse_version("1.0.0") < parse_version("1.1.0")
        assert parse_version("1.0.0") < parse_version("1.0.1")
        assert parse_version("0.9.9") < parse_version("1.0.0")


# ---------------------------------------------------------------------------
# compute_changes
# ---------------------------------------------------------------------------


class TestComputeChanges:
    def test_no_changes(self):
        pkgs = {"lodash": {"4.17.21": "url"}}
        assert compute_changes(pkgs, pkgs) == []

    def test_new_dependency(self):
        base = {}
        head = {"lodash": {"4.17.21": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].name == "lodash"
        assert changes[0].old_version is None
        assert changes[0].new_version == "4.17.21"
        assert changes[0].change_type == "added"
        assert changes[0].new_resolved_url == "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

    def test_removed_dependency_skipped(self):
        base = {"lodash": {"4.17.21": "url"}}
        head = {}
        assert compute_changes(base, head) == []

    def test_upgrade(self):
        base = {"lodash": {"4.17.20": "old_url"}}
        head = {"lodash": {"4.17.21": "new_url"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].change_type == "upgraded"
        assert changes[0].old_resolved_url == "old_url"
        assert changes[0].new_resolved_url == "new_url"

    def test_downgrade(self):
        base = {"lodash": {"4.17.21": "new_url"}}
        head = {"lodash": {"4.17.20": "old_url"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].change_type == "downgraded"

    def test_multiple_deps_changed(self):
        base = {"lodash": {"4.17.20": "a"}, "express": {"4.18.1": "b"}}
        head = {"lodash": {"4.17.21": "c"}, "express": {"4.18.2": "d"}}
        changes = compute_changes(base, head)
        assert len(changes) == 2
        names = {c.name for c in changes}
        assert names == {"lodash", "express"}

    def test_unchanged_deps_excluded(self):
        base = {"lodash": {"4.17.21": "a"}, "express": {"4.18.2": "b"}}
        head = {"lodash": {"4.17.22": "c"}, "express": {"4.18.2": "b"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].name == "lodash"

    def test_sorted_output(self):
        base = {}
        head = {"zebra": {"1.0.0": "z"}, "alpha": {"1.0.0": "a"}, "mid": {"1.0.0": "m"}}
        changes = compute_changes(base, head)
        names = [c.name for c in changes]
        assert names == ["alpha", "mid", "zebra"]


# ---------------------------------------------------------------------------
# is_binary
# ---------------------------------------------------------------------------


class TestIsBinary:
    def test_text_file(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("console.log('hello');\n")
        assert is_binary(f) is False

    def test_binary_file(self, tmp_path):
        f = tmp_path / "test.node"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert is_binary(f) is True

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert is_binary(f) is False

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "nope"
        assert is_binary(f) is True


# ---------------------------------------------------------------------------
# collect_files
# ---------------------------------------------------------------------------


class TestCollectFiles:
    def test_empty_directory(self, tmp_path):
        assert collect_files(tmp_path) == {}

    def test_flat_files(self, tmp_path):
        (tmp_path / "index.js").write_text("module.exports = {}")
        (tmp_path / "package.json").write_text("{}")
        result = collect_files(tmp_path)
        assert set(result.keys()) == {"index.js", "package.json"}

    def test_nested_files(self, tmp_path):
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "utils.js").write_text("")
        result = collect_files(tmp_path)
        assert "lib/utils.js" in result

    def test_uses_forward_slashes(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b").mkdir()
        (tmp_path / "a" / "b" / "c.js").write_text("c")
        result = collect_files(tmp_path)
        assert "a/b/c.js" in result


# ---------------------------------------------------------------------------
# diff_packages
# ---------------------------------------------------------------------------


class TestDiffPackages:
    def test_identical_directories(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "index.js").write_text("module.exports = {};\n")
        (new / "index.js").write_text("module.exports = {};\n")
        assert diff_packages(old, new).strip() == ""

    def test_modified_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "index.js").write_text("module.exports = 'hello';\n")
        (new / "index.js").write_text("module.exports = 'world';\n")
        result = diff_packages(old, new)
        assert "-module.exports = 'hello';" in result
        assert "+module.exports = 'world';" in result

    def test_new_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (new / "new_file.js").write_text("const os = require('os');\n")
        result = diff_packages(old, new)
        assert "+const os = require('os');" in result

    def test_new_dep_none_old_dir(self, tmp_path):
        new = tmp_path / "new"
        new.mkdir()
        (new / "package.json").write_text('{"name": "test"}\n')
        result = diff_packages(None, new)
        assert '+{"name": "test"}' in result

    def test_binary_file_change(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "lib.node").write_bytes(b"\x00" * 100)
        (new / "lib.node").write_bytes(b"\x00" * 200)
        result = diff_packages(old, new)
        assert "Binary file lib.node changed (100 -> 200 bytes)" in result


# ---------------------------------------------------------------------------
# extract_tarball
# ---------------------------------------------------------------------------


class TestExtractTarball:
    def test_tgz(self, tmp_path):
        # Create a fake npm tarball (extracts to package/)
        build = tmp_path / "build"
        build.mkdir()
        inner = build / "package"
        inner.mkdir()
        (inner / "package.json").write_text('{"name": "foo", "version": "1.0.0"}')
        (inner / "index.js").write_text("module.exports = 'foo';\n")

        tarball = tmp_path / "foo-1.0.0.tgz"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(inner, arcname="package")

        dest = tmp_path / "extract"
        dest.mkdir()
        result = extract_tarball(tarball, dest)
        assert result is not None
        assert (result / "package.json").exists()
        assert (result / "index.js").exists()

    def test_tar_gz(self, tmp_path):
        build = tmp_path / "build"
        build.mkdir()
        inner = build / "package"
        inner.mkdir()
        (inner / "package.json").write_text('{"name": "bar", "version": "2.0.0"}')

        tarball = tmp_path / "bar-2.0.0.tar.gz"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(inner, arcname="package")

        dest = tmp_path / "extract"
        dest.mkdir()
        result = extract_tarball(tarball, dest)
        assert result is not None
        assert (result / "package.json").exists()

    def test_invalid_archive(self, tmp_path):
        bad = tmp_path / "bad.tgz"
        bad.write_bytes(b"not a tarball")
        dest = tmp_path / "extract"
        dest.mkdir()
        assert extract_tarball(bad, dest) is None

    def test_unknown_format(self, tmp_path):
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"not relevant")
        dest = tmp_path / "extract"
        dest.mkdir()
        assert extract_tarball(bad, dest) is None


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------


class TestFormatComment:
    def _make_verdict(self, name, old, new, risk, summary="Test.", findings=None):
        change_type = "added" if old is None else "upgraded"
        change = Change(name, old, new, change_type)
        return Verdict(change, risk, summary, findings or [])

    def test_no_high_risk(self):
        verdicts = [self._make_verdict("lodash", "4.17.20", "4.17.21", "none")]
        comment = format_comment(verdicts)
        assert "## Supply Chain Audit" in comment
        assert "No high-risk findings" in comment

    def test_high_risk_expanded(self):
        verdicts = [
            self._make_verdict(
                "evil-pkg", "1.0.0", "1.0.1", "critical",
                "Obfuscated code found.",
                [{"severity": "critical", "description": "eval(Buffer.from(...))", "evidence": "eval(Buffer.from(payload, 'base64'))"}],
            )
        ]
        comment = format_comment(verdicts)
        assert "### " in comment
        assert "eval(Buffer.from(...))" in comment

    def test_low_risk_collapsed(self):
        verdicts = [self._make_verdict("lodash", "4.17.20", "4.17.21", "low")]
        comment = format_comment(verdicts)
        assert "<details>" in comment

    def test_new_dep_formatting(self):
        verdicts = [self._make_verdict("new-pkg", None, "1.0.0", "none")]
        comment = format_comment(verdicts)
        assert "`1.0.0` (new)" in comment

    def test_sorted_by_risk(self):
        verdicts = [
            self._make_verdict("safe", "1.0.0", "1.0.1", "none"),
            self._make_verdict("danger", "1.0.0", "1.0.1", "critical"),
            self._make_verdict("maybe", "1.0.0", "1.0.1", "medium"),
        ]
        comment = format_comment(verdicts)
        crit_pos = comment.index("danger")
        med_pos = comment.index("maybe")
        none_pos = comment.index("safe")
        assert crit_pos < med_pos < none_pos

    def test_truncation(self):
        long_summary = "x" * 70_000
        verdicts = [self._make_verdict("big", "1.0.0", "1.0.1", "low", long_summary)]
        comment = format_comment(verdicts)
        assert len(comment) <= audit.MAX_COMMENT_CHARS
        assert "truncated" in comment

    def test_footer_present(self):
        verdicts = [self._make_verdict("lodash", "4.17.20", "4.17.21", "none")]
        comment = format_comment(verdicts)
        assert "npm-lock-supply-chain-claude" in comment
