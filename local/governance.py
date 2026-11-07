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
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_CONFIG = {
    "protected_branches": ["main", "master"],
    "max_header": 72,
    "commit_types": ["feat", "fix", "docs", "refactor", "test", "chore",
                     "perf", "ci", "build", "revert"],
    "ignore_paths": [".githooks/"],
}

SECRET_RULES = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("credential-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*"
        r"(['\"])(?=[A-Za-z0-9/+_-]*[0-9])(?=[A-Za-z0-9/+_-]*[A-Za-z])"
        r"[A-Za-z0-9/+_-]{16,}\1")),
]

PLACEHOLDER = re.compile(
    r"(?i)(?:\bexample\b|\bsample\b|\bsynthetic\b|\bdummy\b|\bplaceholder\b"
    r"|\bchangeme\b|\bredacted\b|your[_-]?(?:token|key|secret)|<[^>]+>)")
ENV_REFERENCE = re.compile(r"(?:os\.environ|getenv|process\.env|secrets\.)")
SENSITIVE_FILE = re.compile(
    r"(^|/)(?:\.env(?:\.[^/]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|credentials\.json"
    r"|[^/]+\.(?:pem|key|p12|pfx|keystore))$", re.IGNORECASE)
SENSITIVE_EXEMPT = re.compile(
    r"(?i)(?:^|/)(?:\.env\.(?:example|sample|template)|[^/]+\.example\.[^/]+"
    r"|[^/]*_example\.[^/]+)$")
ZERO_SHA = "0" * 40
CONVENTIONAL = r"^(?:%s)(?:\([^)]+\))?!?: .+"


def run(*args, cwd=None, input_text=None):
    return subprocess.run(args, cwd=cwd, input=input_text, capture_output=True,
                          text=True, check=False)


def git(*args, input_text=None):
    return run("git", *args, input_text=input_text)


def config(root):
    path = Path(root) / ".githooks" / "governance.json"
    values = {key: list(value) if isinstance(value, list) else value
              for key, value in DEFAULT_CONFIG.items()}
    if path.is_file():
        loaded = json.loads(path.read_text())
        if not isinstance(loaded, dict):
            raise SystemExit("governance: .githooks/governance.json must be an object")
        values.update(loaded)
    return values


def scan_text(text):
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        if PLACEHOLDER.search(line) or ENV_REFERENCE.search(line):
            continue
        for rule, pattern in SECRET_RULES:
            if pattern.search(line):
                findings.append((number, rule))
                break
    return findings


def tracked_files(root, staged):
    if staged:
        output = git("-C", root, "diff", "--cached", "--name-only", "-z",
                     "--diff-filter=ACMR").stdout
    else:
        output = git("-C", root, "ls-files", "-z").stdout
    return [name for name in output.split("\0") if name]


def read_blobs(root, paths, staged):
    if not paths:
        return {}
    specs = "".join(f"{':' + path if staged else 'HEAD:' + path}\n" for path in paths)
    result = subprocess.run(("git", "-C", root, "cat-file", "--batch"),
                            input=specs.encode(), capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"governance: cannot read tracked objects: {result.stderr.decode(errors='replace').strip()}")
    data = result.stdout
    blobs = {}
    index = 0
    for path in paths:
        end = data.find(b"\n", index)
        if end < 0:
            break
        header = data[index:end].decode("utf-8", "replace").split()
        index = end + 1
        if len(header) < 3:
            blobs[path] = None
            continue
        size = int(header[2])
        content = data[index:index + size]
        index += size + 1
        if header[1] != "blob":
            blobs[path] = None
            continue
        blobs[path] = content.decode("utf-8", errors="replace")
    return blobs


def audit(root, staged, settings):
    findings = []
    paths = []
    for path in tracked_files(root, staged):
        if any(path.startswith(prefix) for prefix in settings["ignore_paths"]):
            continue
        if SENSITIVE_FILE.search(path) and not SENSITIVE_EXEMPT.search(path):
            findings.append(f"{path}: sensitive file is tracked")
            continue
        paths.append(path)
    for path, text in read_blobs(root, paths, staged).items():
        if text is None or "\x00" in text:
            continue
        for number, rule in scan_text(text):
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
        if local_sha == ZERO_SHA or remote_sha == ZERO_SHA:
            continue
        if not is_ancestor(remote_sha, local_sha):
            problems.append(f"non-fast-forward push to {remote_ref}; rebase instead of force-pushing")
    return problems


def hook_pre_commit(root):
    return audit(root, True, config(root))


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


def install(root):
    directory = Path(root) / ".githooks"
    shims = ["pre-commit", "commit-msg", "pre-push"]
    missing = [name for name in shims if not (directory / name).is_file()]
    if missing:
        return [f"missing hook {name} in .githooks/" for name in missing]
    for name in shims:
        (directory / name).chmod(0o755)
    result = git("-C", root, "config", "core.hooksPath", ".githooks")
    if result.returncode != 0:
        return [f"git config failed: {result.stderr.strip()}"]
    return []


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",
                        choices=["audit", "pre-commit", "commit-msg", "pre-push", "install"])
    parser.add_argument("argument", nargs="?")
    parser.add_argument("--staged", action="store_true",
                        help="audit the index instead of the tracked tree")
    parser.add_argument("--root", default=".")
    options = parser.parse_args(argv)
    root = str(Path(options.root).resolve())
    if options.command == "install":
        problems = install(root)
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
