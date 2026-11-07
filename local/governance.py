#!/usr/bin/env python3
"""Local governance for repositories without server-side branch protection.

The private repositories run on a plan that provides neither protected branches
nor secret scanning, and hosted Actions may be blocked by billing. The checks a
public repository enforces in Actions therefore run here instead: staged
secrets, commit headers, direct or forced pushes to a protected branch, and a
publication audit over tracked files.

Every command fails closed and prints the finding that stopped it. The rules are
intentionally conservative: a false positive costs one rewrite, a false negative
publishes a credential.
"""

import argparse
import codecs
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_CONFIG = {
    "protected_branches": ["main", "master"],
    "max_header": 72,
    "commit_types": ["feat", "fix", "docs", "refactor", "test", "chore",
                     "perf", "ci", "build", "revert"],
    "ignore_paths": [],
}

SECRET_RULES = [
    ("private-key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("github-token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("credential-assignment", re.compile(
        r"(?i)(?<![A-Za-z0-9_])[\"']?[A-Za-z0-9_.-]*"
        r"(?:api[_-]?key|secret|token|password|passwd)[\"']?\s*[:=]\s*"
        r"(['\"])(?P<value>[^\"'\s]{16,})\1")),
]

PLACEHOLDER = re.compile(
    r"(?i)(?:\bexample\b|\bsample\b|\bsynthetic\b|\bdummy\b|\bplaceholder\b"
    r"|\bchange[_-]?me\b|\bredacted\b|your[_-]?(?:token|key|secret)|<[^>]+>)")
SENSITIVE_FILE = re.compile(
    r"(^|/)(?:\.env(?:\.[^/]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|credentials\.json"
    r"|[^/]+\.(?:pem|key|p12|pfx|keystore|jks|bks))$", re.IGNORECASE)
SENSITIVE_EXEMPT = re.compile(
    r"(?i)(?:^|/)(?:\.env\.(?:example|sample|template)|[^/]+\.example\.[^/]+"
    r"|[^/]*_example\.[^/]+)$")
TEST_VALUE = re.compile(
    r"(?i)(?:^|[-_.])(?:test|fake|mock|fixture|dummy|synthetic|example|sample"
    r"|placeholder|redacted)(?:$|[-_.])")
SHELL_REFERENCE = re.compile(r'^\$(?:\{[^"\']*\}|[A-Za-z_][A-Za-z0-9_]*)$')
CONSTANT_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
ZERO_SHA = re.compile(r"^0+$")
CONVENTIONAL = r"^(?:%s)(?:\([^)]+\))?!?: .+"


def run(*args, cwd=None, input_text=None):
    return subprocess.run(args, cwd=cwd, input=input_text, capture_output=True,
                          text=True, check=False)


def git(*args, input_text=None):
    return run("git", *args, input_text=input_text)


def git_output(root, *args):
    result = git("-C", root, *args)
    if result.returncode != 0:
        raise SystemExit(f"governance: git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def config(root):
    root = repository_root(root)
    path = None
    common = git("-C", root, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if common.returncode == 0:
        candidate = Path(common.stdout.strip()) / "governance" / "governance.json"
        if candidate.is_file():
            path = candidate
    values = {key: list(value) if isinstance(value, list) else value
              for key, value in DEFAULT_CONFIG.items()}
    if path is not None:
        loaded = json.loads(path.read_text())
        if not isinstance(loaded, dict):
            raise SystemExit("governance: .githooks/governance.json must be an object")
        values.update(loaded)
    for key in ("protected_branches", "commit_types", "ignore_paths"):
        listed = values[key]
        if not isinstance(listed, list) or not all(isinstance(item, str) and item for item in listed):
            raise SystemExit(f"governance: {key} must be a list of non-empty strings")
    if not isinstance(values["max_header"], int) or values["max_header"] < 1:
        raise SystemExit("governance: max_header must be a positive integer")
    return values


def scan_text(text):
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        found = False
        for rule, pattern in SECRET_RULES:
            for match in pattern.finditer(line):
                value = match.group("value") if "value" in pattern.groupindex else match.group(0)
                if any(exemption.search(value) for exemption in
                       (PLACEHOLDER, TEST_VALUE, SHELL_REFERENCE, CONSTANT_NAME)):
                    continue
                findings.append((number, rule))
                found = True
                break
            if found:
                break
    return findings


def tracked_entries(root, staged, changed_only):
    """Return (path, blob sha) for the index or for the committed tree."""
    if staged:
        changed = None
        if changed_only:
            changed = set(filter(None, git_output(
                root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT").split("\0")))
        entries = []
        for record in git_output(root, "ls-files", "-s", "-z").split("\0"):
            if not record:
                continue
            meta, path = record.split("\t", 1)
            mode, sha, _stage = meta.split()
            if mode != "160000" and (changed is None or path in changed):
                entries.append((path, sha))
        return entries
    entries = []
    for record in git_output(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD").split("\0"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        mode, _kind, sha = meta.split()
        if mode != "160000":
            entries.append((path, sha))
    return entries


def read_objects(root, shas):
    unique = sorted(set(shas))
    if not unique:
        return {}
    result = subprocess.run(("git", "-C", root, "cat-file", "--batch"),
                            input="".join(sha + "\n" for sha in unique).encode(),
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit("governance: cannot read tracked objects: "
                         + result.stderr.decode("utf-8", "replace").strip())
    data = result.stdout
    objects = {}
    index = 0
    for sha in unique:
        end = data.find(b"\n", index)
        if end < 0:
            raise SystemExit("governance: truncated object stream")
        header = data[index:end].decode("utf-8", "replace").split()
        index = end + 1
        if len(header) < 3:
            raise SystemExit(f"governance: object {sha} is missing from the object database")
        size = int(header[2])
        content = data[index:index + size]
        index += size + 1
        if header[1] != "blob":
            raise SystemExit(f"governance: object {sha} is a {header[1]}, not a blob")
        objects[sha] = content
    return objects


def text_of(content):
    if content.startswith(codecs.BOM_UTF16_LE) or content.startswith(codecs.BOM_UTF16_BE):
        return content.decode("utf-16", errors="replace")
    if b"\x00" in content:
        half = len(content) // 2
        even = content[0::2].count(0)
        odd = content[1::2].count(0)
        if half and max(even, odd) / half > 0.3:
            encoding = "utf-16-le" if odd > even else "utf-16-be"
            return content.decode(encoding, errors="replace")
        return None
    return content.decode("utf-8", errors="replace")


def ignored(path, prefixes):
    return any(path == prefix or (prefix.endswith("/") and path.startswith(prefix))
               for prefix in prefixes)


def audit(root, staged, settings, changed_only=False):
    root = repository_root(root)
    findings = []
    entries = [(path, sha) for path, sha in tracked_entries(root, staged, changed_only)
               if not ignored(path, settings["ignore_paths"])]
    sensitive = [(path, sha) for path, sha in entries
                 if SENSITIVE_FILE.search(path) and not SENSITIVE_EXEMPT.search(path)]
    sensitive_paths = {path for path, _sha in sensitive}
    findings.extend(f"{path}: sensitive file is tracked" for path in sorted(sensitive_paths))
    candidates = [(path, sha) for path, sha in entries if path not in sensitive_paths]
    objects = read_objects(root, [sha for _path, sha in candidates])
    for path, sha in candidates:
        content = text_of(objects[sha])
        if content is None:
            continue
        for number, rule in scan_text(content):
            findings.append(f"{path}:{number}: {rule}")
    return findings


def check_header(message, settings):
    first = message.splitlines()[0] if message else ""
    if first.startswith("Merge ") or first.startswith('Revert "'):
        return None
    if len(first) > settings["max_header"]:
        return f"commit header is {len(first)} characters (max {settings['max_header']})"
    pattern = CONVENTIONAL % "|".join(re.escape(t) for t in settings["commit_types"])
    if not re.match(pattern, first):
        return "commit header must be `<type>(<scope>): <summary>` with a conventional type"
    return None


def protected_push(lines, settings, is_ancestor):
    problems = []
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        _local_ref, local_sha, remote_ref, remote_sha = parts
        branch = remote_ref.removeprefix("refs/heads/")
        if remote_ref.startswith("refs/heads/") and branch in settings["protected_branches"]:
            problems.append(f"direct push to protected branch {branch}; open a pull request")
        if ZERO_SHA.match(local_sha) or ZERO_SHA.match(remote_sha):
            continue
        if not is_ancestor(remote_sha, local_sha):
            problems.append(f"non-fast-forward push to {remote_ref}; rebase instead of force-pushing")
    return problems


def hook_pre_commit(root):
    return audit(root, True, config(root), changed_only=True)


def hook_commit_msg(root, message_file):
    if not message_file:
        return ["commit-msg hook needs the message file"]
    error = check_header(Path(message_file).read_text(), config(root))
    return [error] if error else []


def hook_pre_push(root, lines):
    settings = config(root)

    def is_ancestor(old, new):
        return git("-C", root, "merge-base", "--is-ancestor", old, new).returncode == 0

    return protected_push(lines, settings, is_ancestor)


def previous_hooks(root, target):
    result = git("-C", root, "config", "--path", "--get", "core.hooksPath")
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = Path(root) / path
    path = path.resolve()
    return path if path != target.resolve() and path.is_dir() else None


def install(root, source=None):
    root = repository_root(root)
    source = Path(source) if source else Path(root) / ".githooks"
    names = ["governance.py", "pre-commit", "commit-msg", "pre-push"]
    missing = [name for name in names if not (source / name).is_file()]
    if missing:
        return [f"missing file {name} in {source}" for name in missing]
    target = Path(git_output(root, "rev-parse", "--path-format=absolute",
                             "--git-common-dir").strip()) / "governance"
    inherited = previous_hooks(root, target)
    target.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copyfile(source / name, target / name)
        (target / name).chmod(0o755)
    policy = source / "governance.json"
    (target / "governance.json").write_text(policy.read_text() if policy.is_file() else "{}\n")
    if inherited is not None:
        for entry in inherited.iterdir():
            if (entry.is_file() and os.access(entry, os.X_OK)
                    and entry.name not in names and not entry.name.startswith(".")):
                shim = target / entry.name
                if not shim.exists():
                    shim.write_text(f"#!/bin/sh\nexec {shlex.quote(str(entry))} \"$@\"\n")
                    shim.chmod(0o755)
    result = git("-C", root, "config", "core.hooksPath", str(target))
    if result.returncode != 0:
        return [f"git config failed: {result.stderr.strip()}"]
    return []


def repository_root(path):
    result = git("-C", path, "rev-parse", "--show-toplevel")
    return result.stdout.strip() if result.returncode == 0 else path


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",
                        choices=["audit", "pre-commit", "commit-msg", "pre-push", "install"])
    parser.add_argument("argument", nargs="?")
    parser.add_argument("--staged", action="store_true",
                        help="audit the index instead of the committed tree")
    parser.add_argument("--root", default=".")
    parser.add_argument("--source", help="directory to install the hooks from")
    options = parser.parse_args(argv)
    root = repository_root(str(Path(options.root).resolve()))
    if options.command == "install":
        problems = install(root, options.source)
    else:
        problems = {
            "audit": lambda: audit(root, options.staged, config(root)),
            "pre-commit": lambda: hook_pre_commit(root),
            "commit-msg": lambda: hook_commit_msg(root, options.argument),
            "pre-push": lambda: hook_pre_push(root, sys.stdin.read().splitlines()),
        }[options.command]()
    for problem in problems:
        print(f"governance: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
