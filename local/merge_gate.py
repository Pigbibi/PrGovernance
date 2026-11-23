#!/usr/bin/env python3
"""Merge entry gate for private repositories.

GitHub Free cannot enforce branch protection on private repositories, and a
status check without a required context blocks nothing. This script moves the
gate to the only action that changes the default branch: the merge itself. It
reads repository facts, refuses when the evidence does not match the change,
and records a machine-readable verdict only after the merge succeeds.

Usage:
    python3 governance/merge_gate.py --pr 93 --dry-run
    python3 governance/merge_gate.py --pr 93
    python3 governance/merge_gate.py --audit --limit 20
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple

API_ROOT = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
USER_AGENT = "repository-merge-gate/1"
VERDICT_MARKER = "governance-verdict:v1"
# A required context is evidence only from the CI platform itself. Any other
# app, or a bare status push under the same name, would otherwise let a
# provider vouch for a job it never ran.
ACTIONS_APP_ID = 15368
ACTIONS_BOT = "github-actions[bot]"
RECEIPT_MARKER_NAMES = (
    "ai-review-receipt:v1",
    "codex-review-receipt:v1",
    "codex-review-state:v1",
)
RECEIPT_MARKER_OPEN = re.compile(
    r"<!--\s*(ai-review-receipt:v1|codex-review-receipt:v1|codex-review-state:v1)"
    r"(?=\s|-->|$|[^A-Za-z0-9_.:-])"
)
COMPLETE_COVERAGE = {"complete", "completed", "full", "reported_complete", "all"}
ALL_REVIEW_PROVIDERS = {"codex", "claude", "cursor", "opencode", "deepseek"}
REVIEWER_PROVIDERS: dict[str, tuple[str, tuple[int, ...]]] = {
    "chatgpt-codex-connector": ("codex", (0, 1, 2)),
    "chatgpt-codex-connector[bot]": ("codex", (0, 1, 2)),
    "claude[bot]": ("claude", (0,)),
    "cursor[bot]": ("cursor", (0,)),
    "pigbibi-local-ai-reviewer": ("opencode", (0,)),
    "pigbibi-local-ai-reviewer[bot]": ("opencode", (0,)),
    "pigbibi-ai-reviewer[bot]": ("opencode", (0,)),
    "qsl-ai-reviewer[bot]": ("opencode", (0,)),
    "gdei-ai-reviewer[bot]": ("opencode", (0,)),
}
ACTION_PIN = re.compile(r"^\s*-?\s*uses\s*:")
ACTION_TARGET = re.compile(
    r"^\s*-?\s*uses\s*:\s*[\"']?([^@\"'\s]+)@([0-9a-f]{40})[\"']?\s*(?:#.*)?$"
)

STRUCTURAL_PATHS = (
    re.compile(r"^\.github/"),
    re.compile(r"^governance/"),
    re.compile(r"(^|/)codeowners$"),
    re.compile(r"(^|/)\.env(?:[./_-]|$)"),
    re.compile(r"(^|/)(agents|claude|skill|instructions?)\.md$"),
    # Behavioural instructions decide what an agent may do; a documentation
    # exemption must not let them change without review.
    re.compile(r"(^|/)(profiles?|skills?)(/|$)"),
    re.compile(r"(^|/)\.agents(/|$)"),
    re.compile(r"(^|/)(dockerfile(?:\..*)?|docker-compose[^/]*|compose\.ya?ml|vercel\.json|wrangler\.(?:toml|jsonc?)|firebase\.json)$"),
    re.compile(r"(^|/)(pyproject\.toml|package\.json|.*\.config\.[^/]+|\.ruff\.toml|ruff-shared\.toml|pyrightconfig\.json|\.importlinter|importlinter\.toml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|\.pre-commit-config\.yaml|knip\.jsonc?|\.jscpd\.json)$"),
    re.compile(r"\.(?:tf|tfvars)$"),
)
DEFAULT_MAX_T1_DIFF_LINES = 500
PROSE_OR_FIXTURE_DIFF = re.compile(r"(?:\.(?:md|txt|rst)$|(?:^|/)fixtures(?:\/|$))", re.IGNORECASE)
TEST_SOURCE_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)(?:/|$)|(?:\.|_)(?:test|spec)\.[^/]+$", re.IGNORECASE)
KEYWORD_PATHS = (
    re.compile(r"(^|[/_.-])(secrets?|credentials?|iam)([/_.-]|$)"),
    re.compile(r"(^|[/_.-])(config|configuration|settings)([/_.-]|$)"),
    re.compile(r"(^|[/_.-])(deploy(?:ment)?|runtime|auth|security)([/_.-]|$)"),
    re.compile(r"(^|[/_.-])(trade|trading|execution|executors?|orders?|brokers?|risk|strateg(?:y|ies))([/_.-]|$)"),
    re.compile(r"^scripts/[^/]*(?:check|verify|validate|hygiene|lint)[^/]*\.(?:py|sh|js|cjs|mjs|ts)$"),
)

# Limit T0 exemptions to Markdown prose files (non-prose under docs/, such as
# docs/conf.py, doc/tool.sh, or docs/requirements.txt, still requires review).
PLAIN_DOC = (
    re.compile(r"\.md$", re.IGNORECASE),
)

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
)
SECRET_ALLOW = re.compile(r"(example|placeholder|dummy|redacted|xxxx|your[_-]|<[^>]+>)", re.I)
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".bz2", ".xz", ".7z", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov",
    ".wav", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".jar", ".class", ".so",
    ".dylib", ".dll", ".exe", ".bin", ".sqlite", ".db",
}


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str = ""):
        super().__init__(f"GitHub API {status}")
        self.status = status
        self.detail = message


class Refusal(RuntimeError):
    pass


def diagnostic(exc: ApiError) -> str:
    return f"GitHub API {exc.status}"


SHA40_RE = re.compile(r"[0-9a-f]{40}")


def _expect_dict(value: Any) -> dict[str, Any] | None:
    """Return value if it is a dict, otherwise None."""
    return value if isinstance(value, dict) else None


def _expect_list(value: Any) -> list[Any] | None:
    """Return value if it is a list, otherwise None."""
    return value if isinstance(value, list) else None


def _expect_str(value: Any, *, non_empty: bool = False, strip: bool = False) -> str | None:
    """Return value if it is a str (optionally stripped and non-empty), otherwise None."""
    if not isinstance(value, str):
        return None
    text = value.strip() if strip else value
    if non_empty and not text:
        return None
    return text


def _expect_bool(value: Any) -> bool | None:
    """Return value if it is strictly a bool, otherwise None."""
    return value if isinstance(value, bool) else None


def _expect_int(value: Any) -> int | None:
    """Return value if it is an int and strictly not a bool, otherwise None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _expect_nonneg_int(value: Any) -> int | None:
    """Return value if it is a non-negative non-bool int, otherwise None."""
    number = _expect_int(value)
    return number if number is not None and number >= 0 else None


def _expect_sha40(value: Any, *, strip: bool = False) -> str | None:
    """Return lowercase 40-char hex SHA if valid, otherwise None."""
    text = _expect_str(value, strip=strip)
    if text is None:
        return None
    lowered = text.lower()
    return lowered if SHA40_RE.fullmatch(lowered) else None


def _dict_at(mapping: Any, *keys: str) -> dict[str, Any]:
    """Safely traverse nested dicts and return {} if any segment is missing or non-dict."""
    current = _expect_dict(mapping)
    for key in keys:
        if current is None:
            return {}
        current = _expect_dict(current.get(key))
    return current or {}


def auth_token() -> str:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    try:
        value = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("No GitHub token: set GH_TOKEN or authenticate gh") from exc
    if not value:
        raise SystemExit("No GitHub token: set GH_TOKEN or authenticate gh")
    return value


TOKEN = None


def _raw_request(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    allow: tuple[int, ...] = (),
) -> tuple[Any, dict[str, str]]:
    global TOKEN
    if TOKEN is None:
        TOKEN = auth_token()
    url = API_ROOT + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {TOKEN}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            headers = {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        if exc.code in allow:
            return None, headers
        try:
            detail = json.loads(raw).get("message", "")
        except (ValueError, AttributeError):
            detail = raw[:200].decode("utf-8", "replace")
        raise ApiError(exc.code, detail) from exc
    if not raw:
        return None, headers
    return json.loads(raw), headers


def request(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    allow: tuple[int, ...] = (),
) -> Any:
    payload, _ = _raw_request(method, path, body=body, params=params, allow=allow)
    return payload


def paginate(path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    page = 1
    items: list[dict[str, Any]] = []
    while True:
        query = dict(params or {})
        query["per_page"] = 100
        query["page"] = page
        chunk = request("GET", path, params=query)
        items.extend(chunk)
        if len(chunk) < 100:
            return items
        page += 1


def _load_policy_file(policy_file: str) -> dict[str, Any]:
    try:
        raw = Path(policy_file).read_bytes()
        policy = json.loads(raw)
    except OSError as exc:
        raise Refusal(f"Cannot read policy file {policy_file}") from exc
    except ValueError as exc:
        raise Refusal(f"Invalid JSON in policy file {policy_file}") from exc
    policy_obj = _expect_dict(policy)
    if policy_obj is None:
        raise Refusal(f"Policy file {policy_file} must contain a JSON object")
    policy_obj["_sha256"] = hashlib.sha256(raw).hexdigest()
    policy_obj["_source"] = f"file:{policy_file}"
    return policy_obj


def _probe_policy(repo: str, ref: str) -> Any:
    return request(
        "GET",
        f"/repos/{repo}/contents/governance/policy.json",
        params={"ref": ref},
        allow=(404,),
    )


def _load_bootstrap_policy_file(repo: str, policy_ref: str, policy_file: str) -> dict[str, Any]:
    """Load a local policy file only while the default branch has no policy."""
    if _probe_policy(repo, policy_ref) is not None:
        raise Refusal(
            f"governance/policy.json already exists on {policy_ref}; "
            "--policy-file applies only to initial bootstrap"
        )
    return _load_policy_file(policy_file)


def load_policy(repo: str, ref: str) -> dict[str, Any]:
    data = _probe_policy(repo, ref)
    if not data:
        raise Refusal(
            f"No governance/policy.json on {ref}; pass a trusted --policy-file to bootstrap"
        )
    raw = base64.b64decode(data["content"])
    policy = json.loads(raw)
    policy_obj = _expect_dict(policy)
    if policy_obj is None:
        raise Refusal(f"governance/policy.json on {ref} must contain a JSON object")
    policy_obj["_sha256"] = hashlib.sha256(raw).hexdigest()
    policy_obj["_source"] = ref
    return policy_obj


def verify_script(repo: str, ref: str) -> None:
    data = request(
        "GET",
        f"/repos/{repo}/contents/governance/merge_gate.py",
        params={"ref": ref},
        allow=(404,),
    )
    if not data:
        print("warning: merge gate is not on the base branch; bootstrap mode", file=sys.stderr)
        return
    expected = hashlib.sha256(base64.b64decode(data["content"])).hexdigest()
    actual = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
    if expected != actual:
        raise Refusal("Local merge gate differs from the base branch; run it from a clean checkout")


def base_action_files(repo: str, ref: str) -> set[str]:
    data = request(
        "GET",
        f"/repos/{repo}/contents/.github/scripts/dependabot-policy.json",
        params={"ref": ref},
        allow=(404,),
    )
    if not data or data.get("type") != "file":
        return set()
    try:
        policy = json.loads(base64.b64decode(data["content"]))
    except (ValueError, TypeError):
        return set()
    policy_obj = _expect_dict(policy)
    values = _expect_list(policy_obj.get("action_files")) if policy_obj is not None else None
    return set(values) if values is not None else set()


def normalized(path: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", path).lower()


def is_structural(path: str) -> bool:
    candidate = normalized(path)
    return any(pattern.search(candidate) for pattern in STRUCTURAL_PATHS)


def is_keyword(path: str) -> bool:
    candidate = normalized(path)
    return any(pattern.search(candidate) for pattern in KEYWORD_PATHS)


def _matches_extra_protected(path: str, extra: tuple[str, ...]) -> bool:
    candidate = normalized(path)
    for prefix in extra:
        text = _expect_str(prefix, non_empty=True)
        if text is not None and (path.startswith(text) or candidate.startswith(normalized(text))):
            return True
    return False


def is_protected(path: str, extra: tuple[str, ...]) -> bool:
    if _matches_extra_protected(path, extra):
        return True
    return is_structural(path) or is_keyword(path)


def is_t0(file: dict[str, Any]) -> bool:
    names = [name for name in (file.get("filename"), file.get("previous_filename")) if name]
    return bool(names) and all(any(pattern.search(name) for pattern in PLAIN_DOC) for name in names)


def same_action(lines: list[tuple[str, str]]) -> bool:
    removed: list[str] = []
    added: list[str] = []
    for sign, text in lines:
        match = ACTION_TARGET.match(text)
        if not match:
            return False
        (removed if sign == "-" else added).append(match.group(1))
    return bool(removed) and removed == added


def action_repin(file: dict[str, Any], allowed: set[str]) -> bool:
    if file.get("filename") not in allowed:
        return False
    patch = _expect_str(file.get("patch"))
    if patch is None:
        return False
    changed: list[tuple[str, str]] = []
    for line in patch.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line[:1] in ("+", "-"):
            changed.append((line[0], line[1:]))
    if not changed or not all(ACTION_PIN.match(text) for _, text in changed):
        return False
    return same_action(changed)


def is_workflow(file: dict[str, Any]) -> bool:
    names = [file.get("filename") or "", file.get("previous_filename") or ""]
    return any(name.startswith(".github/workflows/") for name in names)


def classify(
    files: list[dict[str, Any]], verified_dependabot: bool, allowed_action_files: set[str], extra: tuple[str, ...]
) -> tuple[str, bool]:
    names = [name for file in files for name in (file.get("filename"), file.get("previous_filename")) if name]
    workflows = [file for file in files if is_workflow(file)]
    non_workflow = [name for name in names if not name.startswith(".github/workflows/")]
    fast_path = (
        verified_dependabot
        and bool(workflows)
        and all(action_repin(file, allowed_action_files) for file in workflows)
        # A repin is the only change a verified Dependabot update may skip review
        # with; a requirements or manifest change in the same PR still needs it.
        and not non_workflow
    )
    if fast_path:
        return "T1", True
    if any(is_structural(name) or _matches_extra_protected(name, extra) for name in names):
        return "T2", False
    if files and all(is_t0(file) for file in files):
        return "T0", False
    if any(is_keyword(name) for name in names):
        return "T2", False
    effective_diff = 0
    for file in files:
        fname = file.get("filename") or ""
        if PROSE_OR_FIXTURE_DIFF.search(fname):
            continue
        additions = file.get("additions") or 0
        deletions = file.get("deletions") or 0
        effective_diff += additions + deletions
        if file.get("status") == "added" and not TEST_SOURCE_PATH.search(fname) and additions > DEFAULT_MAX_T1_DIFF_LINES:
            return "T2", False
    if effective_diff > DEFAULT_MAX_T1_DIFF_LINES:
        return "T2", False
    return "T1", False


def scan_secrets(files: list[dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for file in files:
        patch = _expect_str(file.get("patch"))
        if patch is None:
            continue
        for line in patch.split("\n"):
            # GitHub's files endpoint omits ---/+++ diff headers, so a line
            # starting with +++ is an added line beginning with ++.
            if not line.startswith("+"):
                continue
            text = line[1:]
            for pattern in SECRET_PATTERNS:
                match = next(
                    (found for found in pattern.finditer(text) if not SECRET_ALLOW.search(found.group(0))),
                    None,
                )
                if match:
                    hits.append(f"{file.get('filename')}: {pattern.pattern}")
                    break
    return hits


def complete_patch(file: dict[str, Any]) -> bool:
    patch = _expect_str(file.get("patch"))
    additions = _expect_nonneg_int(file.get("additions"))
    deletions = _expect_nonneg_int(file.get("deletions"))
    if patch is None or additions is None or deletions is None:
        return False
    lines = patch.split("\n")
    added = sum(1 for line in lines if line.startswith("+"))
    removed = sum(1 for line in lines if line.startswith("-"))
    return added == additions and removed == deletions and bool(
        patch or (additions == 0 and deletions == 0 and file.get("status") == "renamed")
    )


def unscanned_text(files: list[dict[str, Any]]) -> list[str]:
    missing: list[str] = []
    for file in files:
        if complete_patch(file):
            continue
        if Path(file.get("filename") or "").suffix.lower() in BINARY_EXTENSIONS:
            continue
        # A pure rename and an empty text file (an empty `__init__.py`, for
        # example) carry no diff by design. A zero-change file that is not a
        # rename can still hold data GitHub reports without a patch (a NUL byte
        # makes a `.txt` binary), so its blob size has to confirm the emptiness;
        # an unreadable blob is judged like a truncated diff.
        if file.get("changes") == 0 and (
            file.get("status") == "renamed" or file.get("_size") == 0
        ):
            continue
        missing.append(file.get("filename"))
    return missing


def complete_template(body: str) -> bool:
    text = re.sub(r"<!--[\s\S]*?-->", "", body or "")
    sections = re.findall(r"^#{1,6}\s+(.+)\r?\n([\s\S]*?)(?=^#{1,6}\s|$(?![\s\S]))", text, re.M)
    def present(pattern: re.Pattern[str]) -> bool:
        for heading, content in sections:
            if not pattern.search(heading):
                continue
            remaining = re.sub(r"```[\s\S]*?```", "", content)
            remaining = re.sub(r"[-*]\s*\[[ x]\]", "", remaining).strip()
            if len(remaining) > 3 and not re.fullmatch(
                r"(?i)(TODO|TBD|N/A|Describe the change.*|Which AI tool.*|List the checks.*)", remaining
            ):
                return True
        return False
    return (
        present(re.compile(r"AI|模型|人工智能", re.I))
        and present(re.compile(r"what changed|summary|problem|changes|变更|改动", re.I))
        and present(re.compile(r"how verified|verif|validat|test(?:ing| plan)?|验证|测试", re.I))
    )


def _is_verified_dependabot_commit(commit: Any) -> bool:
    commit_obj = _expect_dict(commit)
    if commit_obj is None:
        return False
    return (
        _dict_at(commit_obj, "author").get("login") == "dependabot[bot]"
        and _dict_at(commit_obj, "committer").get("login") == "web-flow"
        and _dict_at(commit_obj, "commit", "verification").get("verified") is True
    )


def dependabot_head(
    repo: str,
    number: int,
    head: str | None = None,
    comparison: dict[str, Any] | None = None,
) -> bool:
    comparison_obj = _expect_dict(comparison)
    if comparison_obj is not None and "commits" in comparison_obj:
        commits = _expect_list(comparison_obj.get("commits"))
        total = comparison_obj.get("total_commits")
        if commits is None or not commits or len(commits) >= 250:
            return False
        if total is not None and _expect_nonneg_int(total) != len(commits):
            return False
    else:
        commits = paginate(f"/repos/{repo}/pulls/{number}/commits")
        if not commits or len(commits) >= 250:
            return False
    last_commit = _expect_dict(commits[-1])
    if head is not None and (last_commit is None or last_commit.get("sha") != head):
        return False
    return all(_is_verified_dependabot_commit(commit) for commit in commits)


def _parse_review_payload(marker_index: int, raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw)
    except (ValueError, AttributeError):
        return None
    payload_obj = _expect_dict(payload)
    if payload_obj is None:
        return None
    key = "code_review" if marker_index == 2 else "review"
    return _expect_dict(payload_obj.get(key))


_EPOCH_MIN = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
_EPOCH_MAX = dt.datetime.max.replace(tzinfo=dt.timezone.utc)


def _base_change_cutoff(timeline: list[dict[str, Any]] | None) -> dt.datetime | None:
    if not timeline:
        return None
    latest: dt.datetime | None = None
    for event in timeline:
        event_obj = _expect_dict(event)
        if event_obj is None or event_obj.get("event") != "base_ref_changed":
            continue
        ts = _parse_iso_timestamp(event_obj.get("created_at"))
        if ts is None:
            return _EPOCH_MAX
        if latest is None or ts > latest:
            latest = ts
    return latest


def _parse_iso_timestamp(value: Any) -> dt.datetime | None:
    text = _expect_str(value, non_empty=True, strip=True)
    if text is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _receipt_unresolved(review: dict[str, Any]) -> bool | None:
    has_flag: bool | None = None
    count_flag: bool | None = None
    if "has_unresolved_findings" in review:
        has_flag = _expect_bool(review.get("has_unresolved_findings"))
        if has_flag is None:
            return None
    if "unresolved_findings" in review:
        raw_count = review.get("unresolved_findings")
        bool_count = _expect_bool(raw_count)
        if bool_count is not None:
            count_flag = bool_count
        else:
            int_count = _expect_nonneg_int(raw_count)
            if int_count is None:
                return None
            count_flag = int_count > 0
    if has_flag is not None and count_flag is not None:
        return has_flag if has_flag == count_flag else None
    return has_flag if has_flag is not None else count_flag


def _extract_receipt_markers(body: str) -> list[tuple[int, str | None]]:
    """Detect recognized receipt marker prefixes separately from closed HTML payloads."""
    matches: list[tuple[int, str | None]] = []
    for match in RECEIPT_MARKER_OPEN.finditer(body):
        marker_index = RECEIPT_MARKER_NAMES.index(match.group(1))
        start = match.end()
        end = body.find("-->", start)
        payload = None if end < 0 else body[start:end].strip()
        if marker_index == 1 and payload == "":
            continue
        matches.append((marker_index, payload))
    return matches


def _judge_provider_receipt(
    login_provider: str, marker_index: int, raw: str | None, head: str
) -> tuple[str, str, bool | None, bool]:
    if marker_index < 0:
        return (
            "failure",
            f"Ambiguous or disallowed AI review receipt markers in {login_provider} comment",
            True,
            False,
        )
    if raw is None:
        return "error", "AI review receipt is malformed or unterminated", None, False
    review = _parse_review_payload(marker_index, raw)
    if not review:
        return "error", "AI review receipt is not valid JSON", None, False
    commit_sha = _expect_sha40(review.get("commit_sha"))
    on_head = (commit_sha == head.lower()) if commit_sha is not None else None
    if "provider" in review:
        declared = _expect_str(review.get("provider"), strip=True)
        if declared is None or declared.lower() != login_provider:
            return (
                "failure",
                f"AI review receipt provider does not match comment author {login_provider}",
                on_head,
                False,
            )
    status = review.get("status")
    if status != "completed":
        status_str = _expect_str(status)
        label = status_str if status_str is not None and status_str.strip() else "not finished"
        return "pending", f"AI review {label}", on_head, True
    if on_head is None:
        return "error", "AI review receipt is missing a valid commit_sha", None, False
    if not on_head:
        return "failure", "AI review covers another commit, not this head", False, True
    unresolved = _receipt_unresolved(review)
    if unresolved is True:
        return "failure", "AI review still has unresolved findings on this head", True, True
    if unresolved is None:
        return "failure", "AI review findings state is not reported", True, True
    raw_coverage = review.get("coverage")
    if marker_index in (0, 1) or raw_coverage is not None:
        coverage = _expect_str(raw_coverage, strip=True)
        if coverage is None or coverage.lower() not in COMPLETE_COVERAGE:
            return "failure", "AI review coverage is incomplete", True, True
    return "success", f"{login_provider} reviewed this head with no unresolved findings", True, True


class _ProviderReceipt(NamedTuple):
    head_rank: int
    parsed_ts: dt.datetime
    updated_at: str
    cid: int
    seq_idx: int
    state: str
    note: str
    on_head: bool | None
    provider_ok: bool

    @property
    def priority_key(self) -> tuple[int, dt.datetime, str, int, int]:
        return (self.head_rank, self.parsed_ts, self.updated_at, self.cid, self.seq_idx)

    @property
    def order_key(self) -> tuple[dt.datetime, str, int, int]:
        return (self.parsed_ts, self.updated_at, self.cid, self.seq_idx)

    @property
    def time_key(self) -> tuple[dt.datetime, str]:
        return (self.parsed_ts, self.updated_at)


def _collect_latest_provider_receipts(
    comments: list[dict[str, Any]],
    head: str,
    active: set[str],
    base_changed_at: dt.datetime | None,
) -> dict[str, _ProviderReceipt]:
    # Track the latest receipt per allowed provider, preferring current-head or
    # unparseable receipts (`on_head is not False`) over delayed stale-commit
    # receipts so a later off-head comment cannot mask current-head findings.
    latest_by_provider: dict[str, _ProviderReceipt] = {}
    for seq_idx, comment in enumerate(comments):
        login = _dict_at(comment, "user").get("login", "")
        binding = REVIEWER_PROVIDERS.get(login)
        if not binding:
            continue
        login_provider, allowed_indices = binding
        if login_provider not in active:
            continue
        matches = _extract_receipt_markers(comment.get("body") or "")
        if not matches:
            continue
        updated_at = comment.get("updated_at") or comment.get("created_at") or ""
        parsed_cid = _expect_int(comment.get("id"))
        cid = parsed_cid if parsed_cid is not None else 0
        parsed_ts_opt = _parse_iso_timestamp(updated_at)
        parsed_ts = parsed_ts_opt or _EPOCH_MIN
        if base_changed_at is not None and (parsed_ts_opt is None or parsed_ts_opt < base_changed_at):
            state, note, on_head, provider_ok = (
                "pending",
                "AI review predates pull request base change",
                False,
                True,
            )
        else:
            if len(matches) > 1 or matches[0][0] not in allowed_indices:
                marker_index, payload_raw = -1, None
            else:
                marker_index, payload_raw = matches[0]
            state, note, on_head, provider_ok = _judge_provider_receipt(
                login_provider, marker_index, payload_raw, head
            )
        candidate = _ProviderReceipt(
            1 if on_head is not False else 0,
            parsed_ts,
            updated_at,
            cid,
            seq_idx,
            state,
            note,
            on_head,
            provider_ok,
        )
        prev = latest_by_provider.get(login_provider)
        if prev is None or candidate.priority_key > prev.priority_key:
            latest_by_provider[login_provider] = candidate
    return latest_by_provider


def _select_provider_verdict(latest_by_provider: dict[str, _ProviderReceipt]) -> tuple[str, str]:
    judged = sorted(latest_by_provider.values(), key=lambda entry: entry.order_key, reverse=True)
    passing_head = [e for e in judged if e.on_head is True and e.state == "success"]
    failing_head = [e for e in judged if e.on_head is True and e.state in ("error", "failure")]
    pending_head = [e for e in judged if e.on_head is True and e.state == "pending"]

    if passing_head:
        max_pass_ts = max(e.time_key for e in passing_head)
        for entry in judged:
            if entry.on_head is None and entry.time_key >= max_pass_ts:
                return entry.state, entry.note
        for entry in judged:
            if not entry.provider_ok and entry.on_head is not None and entry.time_key >= max_pass_ts:
                return entry.state, entry.note
        if failing_head:
            return failing_head[0].state, failing_head[0].note
        if pending_head:
            return pending_head[0].state, pending_head[0].note
        return passing_head[0].state, passing_head[0].note

    if failing_head:
        return failing_head[0].state, failing_head[0].note
    if pending_head:
        return pending_head[0].state, pending_head[0].note
    return judged[0].state, judged[0].note


def ai_review_verdict(
    repo: str,
    number: int,
    head: str,
    allowed_providers: set[str] | None = None,
    base_changed_at: dt.datetime | None = None,
) -> tuple[str, str]:
    active = ALL_REVIEW_PROVIDERS if allowed_providers is None else (set(allowed_providers) & ALL_REVIEW_PROVIDERS)
    if not active:
        return "pending", "No AI review providers configured"
    comments = paginate(f"/repos/{repo}/issues/{number}/comments")
    latest_by_provider = _collect_latest_provider_receipts(comments, head, active, base_changed_at)
    if not latest_by_provider:
        return "pending", "No AI review receipt on this pull request"
    return _select_provider_verdict(latest_by_provider)


def codex_verdict(
    repo: str,
    number: int,
    head: str,
    base_changed_at: dt.datetime | None = None,
) -> tuple[str, str]:
    return ai_review_verdict(
        repo, number, head, allowed_providers={"codex"}, base_changed_at=base_changed_at
    )


def policy_review_providers(policy: dict[str, Any]) -> set[str]:
    if policy.get("codex_required", True) is True:
        return {"codex"}
    configured = _expect_list(policy.get("ai_review_providers"))
    if configured is None:
        return set()
    providers: set[str] = set()
    for entry in configured:
        name = _expect_str(entry, non_empty=True, strip=True)
        if name is not None and name.lower() in ALL_REVIEW_PROVIDERS:
            providers.add(name.lower())
    return providers


_UNSET = object()


def _clean_logins(configured: Any) -> set[str]:
    entries = _expect_list(configured)
    if entries is None:
        return set()
    cleaned: set[str] = set()
    for login in entries:
        text = _expect_str(login, non_empty=True, strip=True)
        if text is not None:
            cleaned.add(text)
    return cleaned


def policy_agent_logins(policy: dict[str, Any] | None) -> set[str]:
    policy_obj = _expect_dict(policy)
    if policy_obj is None:
        return set()
    configured = _expect_list(policy_obj.get("agent_logins"))
    if configured is None:
        configured = _expect_list(policy_obj.get("approved_agent_logins"))
    return _clean_logins(configured)


def _valid_verdict_signers(policy: dict[str, Any] | None) -> set[str]:
    """Return GitHub logins accepted by audit() as merge verdict signers."""
    policy_obj = _expect_dict(policy)
    if policy_obj is None:
        return set()
    signers = _clean_logins(policy_obj.get("verdict_signers"))
    owner = _expect_str(policy_obj.get("owner_login"), non_empty=True, strip=True)
    if owner is not None:
        signers.add(owner)
    return signers


def _require_verdict_signer(policy: dict[str, Any] | None) -> str:
    signers = _valid_verdict_signers(policy)
    if not signers:
        raise Refusal("Policy configures no valid verdict signer; refusing merge")
    try:
        caller = request("GET", "/user")
    except ApiError as exc:
        raise Refusal(
            f"Cannot verify authenticated GitHub caller ({diagnostic(exc)}); refusing merge"
        ) from exc
    caller_obj = _expect_dict(caller)
    caller_login = _expect_str(caller_obj.get("login") if caller_obj is not None else None, non_empty=True, strip=True)
    if caller_login is None:
        raise Refusal("Cannot identify authenticated GitHub caller; refusing merge")
    if caller_login not in signers:
        raise Refusal(
            f"Authenticated caller {caller_login} is not an audit-accepted verdict signer; "
            "refusing merge"
        )
    return caller_login


def _valid_clearing_actor(
    name: str, event: dict[str, Any], owner: str, agent_logins: set[str] | None = None
) -> bool:
    if event.get("event") != "labeled":
        return False
    actor_login = _dict_at(event, "actor").get("login") or ""
    if name == "owner-approved":
        return bool(owner) and actor_login == owner
    if name == "agent-approved":
        allowed = ({owner} if owner else set()) | set(agent_logins or ())
        return bool(actor_login) and actor_login in allowed
    return False


def branch_activities(activity_repo: str, head_ref: str) -> list[dict[str, Any]] | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", activity_repo):
        return None
    owner_part, repo_part = activity_repo.split("/", 1)
    if owner_part in (".", "..") or repo_part in (".", ".."):
        return None
    entries: list[dict[str, Any]] = []
    cursor: str | None = None
    seen: set[str] = set()
    while True:
        params: dict[str, Any] = {"ref": f"refs/heads/{head_ref}", "per_page": 100}
        if cursor is not None:
            params["after"] = cursor
        chunk, headers = _raw_request(
            "GET",
            f"/repos/{activity_repo}/activity",
            params=params,
            allow=(403, 404),
        )
        chunk_list = _expect_list(chunk)
        if chunk_list is None:
            return None
        entries.extend(chunk_list)
        link_header = headers.get("link", "")
        next_match = re.search(r'<([^>]+)>\s*;\s*(?:[^,]*;\s*)?rel="next"', link_header)
        if not next_match:
            return entries
        next_query = urllib.parse.parse_qs(urllib.parse.urlparse(next_match.group(1)).query)
        next_cursors = next_query.get("after") or []
        next_cursor = next_cursors[0] if next_cursors else ""
        if not next_cursor or next_cursor in seen:
            return None
        seen.add(next_cursor)
        cursor = next_cursor


def _live_label_from_events(
    repo: str, number: int, owner: str, agent_logins: set[str] | None
) -> str | None:
    events = paginate(f"/repos/{repo}/issues/{number}/events")
    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        event_obj = _expect_dict(event)
        if event_obj is None:
            continue
        name = _dict_at(event_obj, "label").get("name")
        if event_obj.get("event") in ("labeled", "unlabeled") and name in ("owner-approved", "agent-approved"):
            latest[name] = event_obj
    for name in ("owner-approved", "agent-approved"):
        event = latest.get(name)
        if event and _valid_clearing_actor(name, event, owner, agent_logins):
            return name
    return None


def _latest_timeline_labels(timeline: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    reset_events = ("committed", "head_ref_force_pushed", "head_ref_restored", "reopened", "base_ref_changed")
    for event in timeline:
        event_obj = _expect_dict(event)
        if event_obj is None:
            continue
        kind = event_obj.get("event")
        if kind in reset_events:
            latest.clear()
            continue
        name = _dict_at(event_obj, "label").get("name")
        if kind in ("labeled", "unlabeled") and name in ("owner-approved", "agent-approved"):
            latest[name] = event_obj
    return latest


def _status_matches_clearing_event(
    statuses: list[dict[str, Any]],
    name: str,
    number: int,
    event_id: Any,
    base_changed_at: dt.datetime | None,
) -> bool:
    if event_id is None or _expect_bool(event_id) is not None:
        return False
    expected = f"{name} for PR {number} at event {event_id} on this head"
    for status in statuses:
        if (
            status.get("context") == "clearing-label"
            and status.get("state") == "success"
            and _dict_at(status, "creator").get("login") == ACTIONS_BOT
            and status.get("description") == expected
        ):
            if base_changed_at is not None:
                status_ts = _parse_iso_timestamp(status.get("updated_at") or status.get("created_at"))
                if status_ts is None or status_ts < base_changed_at:
                    continue
            return True
    return False


def _activity_matches_head(activities: Any, head: str, event_ts: dt.datetime) -> bool:
    if not activities:
        return False
    timed_entries: list[tuple[dt.datetime, dict[str, Any]]] = []
    for entry in activities:
        entry_obj = _expect_dict(entry)
        if entry_obj is None or _expect_str(entry_obj.get("activity_type"), non_empty=True) is None:
            return False
        ts = _parse_iso_timestamp(entry_obj.get("timestamp"))
        if ts is None:
            return False
        timed_entries.append((ts, entry_obj))
    if not timed_entries:
        return False
    newest_ts, newest = max(timed_entries, key=lambda pair: pair[0])
    return (
        newest.get("activity_type") != "branch_deletion"
        and newest.get("after") == head
        and event_ts >= newest_ts
    )


def live_label(
    repo: str,
    number: int,
    owner: str,
    pull: dict[str, Any] | None = None,
    agent_logins: set[str] | None = None,
    timeline: list[dict[str, Any]] | None = None,
) -> str | None:
    if pull is None:
        return _live_label_from_events(repo, number, owner, agent_logins)

    present = {(lbl.get("name") or "") for lbl in (pull.get("labels") or [])}
    if not (present & {"owner-approved", "agent-approved"}):
        return None
    head_info = _dict_at(pull, "head")
    head = head_info.get("sha") or ""
    if not head:
        return None
    if timeline is None:
        timeline = paginate(f"/repos/{repo}/issues/{number}/timeline")
    base_changed_at = _base_change_cutoff(timeline)
    latest = _latest_timeline_labels(timeline)

    statuses: list[dict[str, Any]] | None = None
    activities: Any = _UNSET
    head_repo = _dict_at(head_info, "repo").get("full_name") or ""
    head_ref = head_info.get("ref") or ""
    for name in ("owner-approved", "agent-approved"):
        if name not in present:
            continue
        event = latest.get(name)
        if not event or not _valid_clearing_actor(name, event, owner, agent_logins):
            continue
        event_ts = _parse_iso_timestamp(event.get("created_at"))
        if base_changed_at is not None and (event_ts is None or event_ts < base_changed_at):
            continue
        if statuses is None:
            statuses = paginate(f"/repos/{repo}/commits/{head}/statuses")
        if _status_matches_clearing_event(statuses, name, number, event.get("id"), base_changed_at):
            return name
        if not head_repo or not head_ref or event_ts is None:
            continue
        if activities is _UNSET:
            activities = branch_activities(head_repo, head_ref)
        if _activity_matches_head(activities, head, event_ts):
            return name
    return None


def head_comparison(repo: str, base: str, head: str) -> tuple[bool, str, dict[str, Any]]:
    branch = request("GET", f"/repos/{repo}/branches/{urllib.parse.quote(base, safe='')}")
    base_head = branch["commit"]["sha"]
    comparison = request("GET", f"/repos/{repo}/compare/{base_head}...{head}") or {}
    contains_base = (comparison.get("merge_base_commit") or {}).get("sha") == base_head
    return contains_base, base_head, comparison


def head_contains_base(repo: str, base: str, head: str) -> tuple[bool, str]:
    contains_base, base_head, _ = head_comparison(repo, base, head)
    return contains_base, base_head


def shared_head(repo: str, number: int, head: str) -> bool:
    return any(
        pull.get("number") != number and (pull.get("head") or {}).get("sha") == head
        for pull in paginate(f"/repos/{repo}/pulls", {"state": "open"})
    )


def check_runs(repo: str, sha: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    page = 1
    while True:
        chunk = request(
            "GET",
            f"/repos/{repo}/commits/{sha}/check-runs",
            params={"per_page": 100, "page": page},
        )
        batch = chunk.get("check_runs") or []
        runs.extend(batch)
        if len(batch) < 100:
            return runs
        page += 1


def checks_state(repo: str, sha: str) -> list[tuple[str, str, int | None]]:
    # Every page of both collections matters: stopping at the first page would
    # let a later failing or queued check escape the verdict.
    runs = check_runs(repo, sha)
    statuses = paginate(f"/repos/{repo}/commits/{sha}/statuses")
    combined = request("GET", f"/repos/{repo}/commits/{sha}/status")
    entries: list[tuple[str, str, int | None]] = []
    for run in runs:
        conclusion = run.get("conclusion")
        state = (
            "success" if conclusion == "success"
            else "skipped" if conclusion in ("neutral", "skipped")
            else "pending" if run.get("status") != "completed"
            else "failure"
        )
        entries.append((run.get("name") or "check", state, (run.get("app") or {}).get("id")))
    # /statuses returns every update of a context, newest first. Only the first
    # record per context describes it now; older pending or failed records are
    # superseded, unlike distinct check runs that share a name. Keeping the API
    # order also survives two updates with the same created_at.
    latest: dict[str, tuple[str, int | None]] = {}
    for status in statuses:
        context = status.get("context") or "status"
        if context in latest:
            continue
        raw = status.get("state")
        state = "success" if raw == "success" else "pending" if raw == "pending" else "failure"
        # A legacy status names no app; its creator is the only issuer fact.
        creator = (status.get("creator") or {}).get("login")
        latest[context] = (state, ACTIONS_APP_ID if creator == ACTIONS_BOT else None)
    entries.extend((name, state, app) for name, (state, app) in latest.items())
    # The combined state also reports "pending" when no legacy status exists,
    # so it carries information only when there is at least one.
    raw_combined = combined.get("state")
    if statuses and raw_combined in ("failure", "pending"):
        entries.append(("combined status", raw_combined, None))
    return entries


def required_contexts(policy: dict[str, Any], verified_dependabot: bool) -> list[str]:
    names = policy.get(
        "dependabot_required_checks" if verified_dependabot else "required_checks"
    )
    if not names:
        names = policy.get("required_checks")
    result: list[str] = []
    for name in names or []:
        text = _expect_str(name, non_empty=True)
        if text is not None:
            result.append(text)
    return result


def applicable_contexts(
    policy: dict[str, Any], verified_dependabot: bool, files: list[dict[str, Any]]
) -> list[str]:
    required = required_contexts(policy, verified_dependabot)
    skipped = _expect_dict(policy.get("ci_skipped_checks"))
    if skipped is None:
        return required
    names = {
        name
        for file in files
        for name in (file.get("filename"), file.get("previous_filename"))
        if name
    }
    if not names:
        return required
    for context, patterns in skipped.items():
        pattern_list = _expect_list(patterns)
        if context not in required or pattern_list is None:
            continue
        globs = [text for text in (_expect_str(p) for p in pattern_list) if text is not None]
        # A workflow's paths-ignore filter only skips a context when every
        # changed file matches; one source file still runs it.
        if globs and all(any(fnmatch.fnmatch(name, glob) for glob in globs) for name in names):
            required = [name for name in required if name != context]
    return required


def check_results(
    repo: str, sha: str, required: list[str]
) -> tuple[list[str], list[str], list[str], list[str]]:
    states: dict[str, list[tuple[str, int | None]]] = {}
    for name, state, app in checks_state(repo, sha):
        states.setdefault(name, []).append((state, app))

    def from_ci(name: str) -> bool:
        # A required context is only as good as its issuer: a check run from
        # another app, or a status pushed by something other than the Actions
        # bot, reports on a job that is not this repository's CI.
        return any(app == ACTIONS_APP_ID for _, app in states[name])

    missing = [name for name in required if name not in states or not from_ci(name)]
    # Every run of a mandatory context must succeed. Keeping only the first
    # run would let a second, failing report of the same job name disappear.
    unsettled = [
        name
        for name in required
        if name in states and any(state != "success" for state, _ in states[name])
    ]
    # A queued check blocks even outside the required list: accepting a head
    # while an optional job is still running would judge it before that job
    # reports. Intentionally skipped jobs stay allowed.
    pending = sorted(name for name, values in states.items() if any(s == "pending" for s, _ in values))
    failing = sorted(name for name, values in states.items() if any(s == "failure" for s, _ in values))
    return missing, unsettled, pending, failing


def _index_tree_entries(raw_tree: Any) -> dict[str, dict[str, Any]] | None:
    tree_list = _expect_list(raw_tree)
    if tree_list is None:
        return None
    indexed: dict[str, dict[str, Any]] = {}
    for entry in tree_list:
        entry_obj = _expect_dict(entry)
        if entry_obj is None:
            continue
        path = _expect_str(entry_obj.get("path"))
        if path is not None:
            indexed[path] = entry_obj
    return indexed


def _resolve_tree_mode(
    repo: str, head: str, path: str, tree_cache: dict[str, dict[str, dict[str, Any]] | None]
) -> tuple[bool, bool]:
    """Resolve (resolved_ok, is_symlink) for path by walking Git tree objects."""
    parts = [part for part in path.split("/") if part]
    if not parts:
        return False, False
    current_sha = head
    for idx, segment in enumerate(parts):
        if current_sha not in tree_cache:
            data_obj = _expect_dict(
                request("GET", f"/repos/{repo}/git/trees/{current_sha}", allow=(404,))
            )
            indexed = _index_tree_entries(data_obj.get("tree")) if data_obj is not None else None
            tree_cache[current_sha] = indexed
            if indexed is None:
                return False, False
        entries = tree_cache[current_sha]
        if entries is None:
            return False, False
        entry = entries.get(segment)
        if not entry:
            return False, False
        if entry.get("mode") == "120000":
            return True, True
        if idx < len(parts) - 1:
            if entry.get("type") != "tree" or not entry.get("sha"):
                return False, False
            current_sha = entry["sha"]
    return True, False


def symlink_entries(
    repo: str, head: str, files: list[dict[str, Any]]
) -> tuple[list[str], bool]:
    checked: list[str] = []
    for file in files:
        if file.get("status") == "removed":
            continue
        name = _expect_str(file.get("filename"), non_empty=True)
        if name is not None:
            checked.append(name)
    if not checked:
        return [], True
    tree_obj = _expect_dict(
        request(
            "GET",
            f"/repos/{repo}/git/trees/{head}",
            params={"recursive": "1"},
            allow=(404,),
        )
    )
    entries = _index_tree_entries(tree_obj.get("tree")) if tree_obj is not None else None
    if tree_obj is None or entries is None:
        return [], False
    modes = {path: entry.get("mode") for path, entry in entries.items()}
    flagged: list[str] = []
    tree_cache: dict[str, dict[str, dict[str, Any]] | None] = {}
    truncated = bool(tree_obj.get("truncated"))
    for path in checked:
        parts = [part for part in path.split("/") if part]
        if not parts:
            return [], False
        prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
        if any(modes.get(prefix) == "120000" for prefix in prefixes):
            flagged.append(path)
            continue
        if path in modes and not (truncated and any(prefix not in modes for prefix in prefixes)):
            continue
        if not truncated:
            return [], False
        ok, is_symlink = _resolve_tree_mode(repo, head, path, tree_cache)
        if not ok:
            return [], False
        if is_symlink:
            flagged.append(path)
    return flagged, True


def _review_verdict_for_policy(
    repo: str,
    number: int,
    head: str,
    providers: set[str],
    base_changed_at: dt.datetime | None,
) -> tuple[str, str]:
    if providers == {"codex"}:
        return codex_verdict(repo, number, head, base_changed_at=base_changed_at)
    return ai_review_verdict(
        repo,
        number,
        head,
        allowed_providers=providers,
        base_changed_at=base_changed_at,
    )


def _load_eval_policy(repo: str, policy_ref: str, policy_file: str | None) -> tuple[dict[str, Any], bool]:
    if policy_file:
        policy = _load_bootstrap_policy_file(repo, policy_ref, policy_file)
        print(
            f"warning: using trusted --policy-file ({policy_file}) instead of {policy_ref} (bootstrap)",
            file=sys.stderr,
        )
        return policy, True
    return load_policy(repo, policy_ref), False


def _hydrate_zero_change_sizes(repo: str, files: list[dict[str, Any]], symlink_set: set[str]) -> None:
    for file in files:
        if file.get("filename") in symlink_set:
            continue
        if complete_patch(file) or file.get("changes") != 0:
            continue
        if Path(file.get("filename") or "").suffix.lower() in BINARY_EXTENSIONS:
            continue
        if not file.get("sha"):
            continue
        blob = _expect_dict(request("GET", f"/repos/{repo}/git/blobs/{file['sha']}", allow=(404,)))
        file["_size"] = blob.get("size") if blob is not None else None


def _evaluate_checks(
    repo: str,
    head: str,
    policy: dict[str, Any],
    verified_dependabot: bool,
    files: list[dict[str, Any]],
    bootstrap: bool,
) -> tuple[str, list[str], str, list[str]]:
    if not policy.get("require_checks", True):
        checks_note = policy.get("checks_disabled_reason") or "not required by policy"
        if bootstrap:
            checks_note += " (policy read from --policy-file; the entry is not installed yet)"
        return "skipped", [], checks_note, []
    required = applicable_contexts(policy, verified_dependabot, files)
    if not required:
        return "missing", [], "", ["CI is required but no applicable context remains"]
    missing, unsettled, pending, failing = check_results(repo, head, required)
    reasons: list[str] = []
    if missing:
        reasons.append("CI did not report required contexts: " + ", ".join(missing[:5]))
    if unsettled:
        reasons.append("CI has not succeeded: " + ", ".join(unsettled[:5]))
    if pending:
        reasons.append("CI is still running: " + ", ".join(pending[:5]))
    if failing:
        reasons.append("CI is not successful: " + ", ".join(failing[:5]))
    checks = (
        "pending" if pending and not (missing or unsettled or failing)
        else "failure" if (missing or unsettled or failing)
        else "success"
    )
    checks_note = (
        "The merge entry is not on the default branch yet; the contexts come from "
        "the trusted --policy-file"
        if bootstrap else ""
    )
    return checks, required, checks_note, reasons


def _evaluate_diff_and_tree(
    repo: str, number: int, pull: dict[str, Any], head: str, base_ref: str
) -> tuple[str, dict[str, Any], list[dict[str, Any]], list[str], bool, list[str]]:
    contains_base, base_head, comparison = head_comparison(repo, base_ref, head)
    comparison_obj = _expect_dict(comparison)
    raw_files = _expect_list(comparison_obj.get("files")) if comparison_obj is not None else None
    valid_files = raw_files is not None and all(_expect_dict(item) is not None for item in raw_files)
    files = raw_files if valid_files else []
    reasons: list[str] = []
    if not valid_files or len(files) >= 300 or len(files) != pull.get("changed_files"):
        reasons.append("Changed-file list is incomplete; refuse to judge a partial diff")
    if not contains_base:
        reasons.append("Base branch advanced since this head was built; update the branch first")
    if shared_head(repo, number, head):
        reasons.append("Another open pull request shares this head; verdicts would collide")
    symlinks, tree_ok = symlink_entries(repo, head, files)
    if symlinks:
        reasons.append(
            "Symlink entries are not allowed in pull requests: " + ", ".join(sorted(symlinks)[:5])
        )
    if not tree_ok:
        reasons.append("Cannot verify Git tree modes for changed files")
    _hydrate_zero_change_sizes(repo, files, set(symlinks))
    return base_head, comparison, files, symlinks, tree_ok, reasons


def _evaluate_review_and_label(
    repo: str,
    number: int,
    pull: dict[str, Any],
    head: str,
    policy: dict[str, Any],
    tier: str,
    fast_path: bool,
    verified_dependabot: bool,
) -> tuple[str, set[str], str | None, list[str]]:
    reasons: list[str] = []
    providers = policy_review_providers(policy)
    needs_review = bool(providers and tier != "T0" and not fast_path)
    timeline = (
        paginate(f"/repos/{repo}/issues/{number}/timeline")
        if (needs_review or tier == "T2")
        else None
    )
    base_changed_at = _base_change_cutoff(timeline) if timeline is not None else None
    if needs_review:
        codex_state, codex_note = _review_verdict_for_policy(
            repo, number, head, providers, base_changed_at
        )
    else:
        codex_state, codex_note = "skipped", "Not required for this change"
    if codex_state not in ("success", "skipped"):
        reasons.append(codex_note)
    agent_logins = policy_agent_logins(policy)
    label = (
        live_label(
            repo,
            number,
            policy.get("owner_login", ""),
            pull=pull,
            agent_logins=agent_logins,
            timeline=timeline,
        )
        if tier == "T2"
        else None
    )
    if tier == "T2" and label is None:
        reasons.append("Protected paths need a live owner-approved or agent-approved label")
    if tier == "T2" and policy.get("require_owner_label_for_protected") and label != "owner-approved":
        reasons.append("This repository requires owner-approved for protected paths")
    if tier == "T2" and not verified_dependabot and not complete_template(pull.get("body") or ""):
        reasons.append("Fill in the AI, What changed and How verified sections")
    return codex_state, providers, label, reasons


def evaluate(repo: str, number: int, policy_file: str | None = None) -> tuple[dict[str, Any], list[str]]:
    pull = request("GET", f"/repos/{repo}/pulls/{number}")
    if pull.get("state") != "open":
        raise Refusal(f"Pull request #{number} is {pull.get('state')}, not open")
    if pull.get("draft"):
        raise Refusal(f"Pull request #{number} is a draft; mark it ready before merging")
    head = pull["head"]["sha"]
    base_ref = pull["base"]["ref"]
    policy_ref = request("GET", f"/repos/{repo}")["default_branch"]
    policy, bootstrap = _load_eval_policy(repo, policy_ref, policy_file)
    verify_script(repo, policy_ref)

    base_head, comparison, files, symlinks, tree_ok, reasons = _evaluate_diff_and_tree(
        repo, number, pull, head, base_ref
    )
    verified_dependabot = (
        _dict_at(pull, "user").get("login") == "dependabot[bot]"
        and dependabot_head(repo, number, head=head, comparison=comparison)
    )
    extra = tuple(policy.get("extra_protected_paths") or ())
    tier, fast_path = classify(files, verified_dependabot, base_action_files(repo, policy_ref), extra)
    if symlinks or not tree_ok:
        tier = "T2"
        fast_path = False

    codex_state, providers, label, review_reasons = _evaluate_review_and_label(
        repo, number, pull, head, policy, tier, fast_path, verified_dependabot
    )
    reasons.extend(review_reasons)

    hits = scan_secrets(files)
    if hits:
        reasons.append("Possible secret in the diff: " + "; ".join(sorted(set(hits))[:5]))
    unscanned = [file.get("filename") for file in files if not complete_patch(file)]
    unscannable = unscanned_text(files)
    if unscannable:
        reasons.append("Cannot scan text changes without a diff: " + ", ".join(unscannable[:5]))

    checks, required, checks_note, check_reasons = _evaluate_checks(
        repo, head, policy, verified_dependabot, files, bootstrap
    )
    reasons.extend(check_reasons)

    verdict = {
        "repo": repo,
        "pr": number,
        "head_sha": head,
        "base_ref": base_ref,
        "policy_ref": policy_ref,
        "base_sha": base_head,
        "tier": tier,
        "codex": codex_state,
        "review_providers": sorted(providers),
        "label": label,
        "confirmed_by_owner": label == "owner-approved",
        "checks": checks,
        "required_checks": required,
        "checks_note": checks_note,
        "bootstrap": bootstrap,
        "body_sha256": hashlib.sha256((pull.get("body") or "").encode()).hexdigest(),
        "policy_sha256": policy.get("_sha256"),
        "verdict": "pass" if not reasons else "fail",
        "reasons": reasons,
        "unscanned": unscanned,
        "merge_method": policy.get("merge_method", "squash"),
    }
    return verdict, reasons


def _revalidate_with_policy(
    repo: str, verdict: dict[str, Any], policy_file: str | None = None
) -> dict[str, Any]:
    pull = request("GET", f"/repos/{repo}/pulls/{verdict['pr']}")
    if pull.get("state") != "open":
        raise Refusal("Pull request is no longer open; re-run the gate")
    if pull["head"]["sha"] != verdict["head_sha"]:
        raise Refusal("Head moved since the verdict; re-run the gate")
    if (pull.get("base") or {}).get("ref") != verdict["base_ref"]:
        raise Refusal("Target branch changed since the verdict; re-run the gate")
    if hashlib.sha256((pull.get("body") or "").encode()).hexdigest() != verdict.get("body_sha256"):
        raise Refusal("Pull request body changed since the verdict; re-run the gate")
    policy_ref = verdict.get("policy_ref") or verdict["base_ref"]
    if policy_file:
        policy = _load_bootstrap_policy_file(repo, policy_ref, policy_file)
        if not verdict.get("bootstrap"):
            raise Refusal("--policy-file applies only to initial bootstrap verdicts; re-run the gate")
    else:
        policy = load_policy(repo, policy_ref)
    if policy.get("_sha256") != verdict.get("policy_sha256"):
        raise Refusal("Policy changed since the verdict; re-run the gate")
    verify_script(repo, policy_ref)
    contains_base, base_head = head_contains_base(repo, verdict["base_ref"], verdict["head_sha"])
    if not contains_base or base_head != verdict.get("base_sha"):
        raise Refusal("Base advanced since the verdict; re-run the gate")
    if shared_head(repo, verdict["pr"], verdict["head_sha"]):
        raise Refusal("Another open pull request now shares this head; re-run the gate")
    needs_label = verdict.get("tier") == "T2"
    needs_review = verdict.get("codex") not in (None, "skipped")
    timeline = (
        paginate(f"/repos/{repo}/issues/{verdict['pr']}/timeline")
        if (needs_label or needs_review)
        else None
    )
    base_changed_at = _base_change_cutoff(timeline) if timeline is not None else None
    if needs_label:
        live = live_label(
            repo,
            verdict["pr"],
            policy.get("owner_login", ""),
            pull=pull,
            agent_logins=policy_agent_logins(policy),
            timeline=timeline,
        )
        if live != verdict.get("label"):
            raise Refusal("Clearing label changed since the verdict; re-run the gate")
    if needs_review:
        providers = policy_review_providers(policy)
        if not providers:
            raise Refusal("AI review policy changed since the verdict; re-run the gate")
        expected_providers = verdict.get("review_providers")
        if expected_providers is not None and sorted(providers) != sorted(expected_providers):
            raise Refusal("AI review providers changed since the verdict; re-run the gate")
        state, note = _review_verdict_for_policy(
            repo, verdict["pr"], verdict["head_sha"], providers, base_changed_at
        )
        if state != "success":
            raise Refusal(f"AI review is no longer valid: {note}; re-run the gate")
    if policy.get("require_checks", True) and verdict.get("required_checks"):
        required = verdict["required_checks"]
        missing, unsettled, pending, failing = check_results(
            repo, verdict["head_sha"], required
        )
        if missing or unsettled or pending or failing:
            raise Refusal("CI evidence changed since the verdict; re-run the gate")
    return policy


def revalidate(repo: str, verdict: dict[str, Any], policy_file: str | None = None) -> None:
    _revalidate_with_policy(repo, verdict, policy_file=policy_file)


@contextlib.contextmanager
def merge_lock(repo: str, base_ref: str):
    """Serialize merges into one base branch from this host.

    GitHub's merge API constrains the head, not the base, so two gates that
    revalidate the same base could both merge and the later one would land on a
    base it never checked. The lock keeps the revalidation and the merge call in
    one critical section for every run on this host.
    """
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - POSIX only
        raise Refusal("This platform cannot serialize merges; refusing") from exc
    key = hashlib.sha256(f"{repo}\n{base_ref}".encode()).hexdigest()[:32]
    path = Path(tempfile.gettempdir()) / f"merge-gate-{key}.lock"
    handle = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def merge(repo: str, verdict: dict[str, Any], policy_file: str | None = None) -> dict[str, Any]:
    number = verdict["pr"]
    with merge_lock(repo, verdict["base_ref"]):
        policy = _revalidate_with_policy(repo, verdict, policy_file=policy_file)
        _require_verdict_signer(policy)
        result = request(
            "PUT",
            f"/repos/{repo}/pulls/{number}/merge",
            body={"sha": verdict["head_sha"], "merge_method": verdict["merge_method"]},
        )
    if not result or not result.get("merged"):
        raise Refusal("Merge refused by GitHub; inspect the pull request state and re-run the gate")
    verdict["merged"] = True
    verdict["merge_sha"] = result.get("sha")
    verdict["at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    body = (
        f"<!-- {VERDICT_MARKER} {json.dumps(verdict, separators=(',', ':'))} -->\n\n"
        f"Merge gate passed at `{verdict['head_sha'][:7]}` ({verdict['tier']}, "
        f"{verdict['label'] or 'no label'}, CI {verdict['checks']})."
    )
    for attempt in range(2):
        try:
            request("POST", f"/repos/{repo}/issues/{number}/comments", body={"body": body})
            break
        except ApiError as exc:
            if attempt:
                print(
                    f"warning: merged but the verdict comment failed ({diagnostic(exc)})",
                    file=sys.stderr,
                )
    return result


def _resolve_commit(repo: str, sha: str, indexed: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    commit = indexed.get(sha)
    if commit is not None:
        return commit
    commit = request("GET", f"/repos/{repo}/commits/{sha}", allow=(404,))
    if commit is not None:
        indexed[sha] = commit
    return commit


def _first_parent_shas(listing: list[dict[str, Any]]) -> set[str]:
    indexed: dict[str, dict[str, Any]] = {}
    for commit in listing:
        commit_obj = _expect_dict(commit)
        sha = _expect_str(commit_obj.get("sha")) if commit_obj is not None else None
        if commit_obj is not None and sha is not None:
            indexed[sha] = commit_obj
    reachable: set[str] = set()
    first_obj = _expect_dict(listing[0]) if listing else None
    current: Any = first_obj.get("sha") if first_obj is not None else ""
    while (current_sha := _expect_str(current, non_empty=True)) is not None and current_sha.lower() not in reachable:
        reachable.add(current_sha.lower())
        commit = indexed.get(current_sha)
        if not commit:
            break
        parents = [
            parent_obj.get("sha")
            for parent in (commit.get("parents") or [])
            if (parent_obj := _expect_dict(parent)) is not None
        ]
        current = parents[0] if parents else ""
    return reachable


def _commit_is_ancestor(
    repo: str, ancestor: str, tip: str, known_ancestors: set[str] | None = None
) -> bool:
    if not ancestor or not tip:
        return False
    lowered = ancestor.lower()
    if lowered == tip.lower() or (known_ancestors is not None and lowered in known_ancestors):
        return True
    comparison = _expect_dict(
        request(
            "GET",
            f"/repos/{repo}/compare/{ancestor}...{tip}",
            allow=(404, 422),
        )
    )
    if comparison is None:
        return False
    merge_base = _expect_str(_dict_at(comparison, "merge_base_commit").get("sha"))
    if merge_base is None or merge_base.lower() != lowered:
        return False
    status = comparison.get("status")
    return status is None or status in ("identical", "ahead")


def _audit_force_pushes(
    repo: str,
    default: str,
    since: str,
    acknowledged: dict[str, Any],
    baseline_sha: str = "",
    baseline_verified: bool = False,
    strict: bool = True,
) -> list[str]:
    activities = branch_activities(repo, default)
    if activities is None:
        message = f"cannot verify force-push activity on {default}; branch activity log is unavailable"
        if strict:
            return [message]
        print(f"warning: {message}")
        return []
    if not activities:
        return []
    expected_ref = f"refs/heads/{default}"
    since_dt = _parse_iso_timestamp(since) if since else None
    findings: list[str] = []
    for entry in activities:
        entry_obj = _expect_dict(entry)
        if entry_obj is None or entry_obj.get("activity_type") != "force_push":
            continue
        entry_ref = entry_obj.get("ref")
        if entry_ref is not None and entry_ref != expected_ref:
            continue
        entry_ts = _parse_iso_timestamp(entry_obj.get("timestamp"))
        if since_dt is not None and entry_ts is not None and entry_ts < since_dt:
            continue
        entry_id = entry_obj.get("id")
        id_key = str(entry_id) if entry_id is not None and _expect_bool(entry_id) is None else ""
        note = ""
        if id_key:
            note = str(acknowledged.get(f"activity:{id_key}") or acknowledged.get(id_key) or "")
        if note:
            print(f"note: acknowledged force push on {default} ({id_key}): {note}")
            continue
        before = str(entry_obj.get("before") or "")
        after = str(entry_obj.get("after") or "")
        if (
            baseline_sha
            and baseline_verified
            and before
            and after
            and not re.fullmatch(r"0+", before)
            and not re.fullmatch(r"0+", after)
            and before.lower() != baseline_sha
            and after.lower() != baseline_sha
            and _commit_is_ancestor(repo, before, baseline_sha)
            and _commit_is_ancestor(repo, after, baseline_sha)
        ):
            continue
        origin = before[:7] if before else "unknown"
        target = after[:7] if after else "unknown"
        event_label = f"activity {id_key}" if id_key else "activity"
        findings.append(f"force push on {default} ({event_label}: {origin}..{target})")
    return findings


def _rebased_commit_matches(step_commit: dict[str, Any], pr_commit: dict[str, Any]) -> bool:
    step_sha = _expect_str(step_commit.get("sha"), non_empty=True)
    pr_sha = _expect_str(pr_commit.get("sha"), non_empty=True)
    if step_sha is not None and step_sha == pr_sha:
        return True
    step_meta = _expect_dict(step_commit.get("commit"))
    pr_meta = _expect_dict(pr_commit.get("commit"))
    if step_meta is None or pr_meta is None:
        return False
    step_message = _expect_str(step_meta.get("message"))
    pr_message = _expect_str(pr_meta.get("message"), non_empty=True)
    if step_message is None or pr_message is None or step_message != pr_message:
        return False
    step_author = _expect_dict(step_meta.get("author"))
    pr_author = _expect_dict(pr_meta.get("author"))
    if step_author is None or pr_author is None:
        return False
    pr_email = _expect_str(pr_author.get("email"), non_empty=True)
    if pr_email is None or step_author.get("email") != pr_email:
        return False
    pr_date = _expect_str(pr_author.get("date"), non_empty=True)
    if pr_date is None or step_author.get("date") != pr_date:
        return False
    pr_name = _expect_str(pr_author.get("name"), non_empty=True)
    if pr_name is not None and step_author.get("name") != pr_name:
        return False
    return True


def _commit_tree_sha(commit: dict[str, Any]) -> str:
    return _expect_sha40(_dict_at(commit, "commit", "tree").get("sha"), strip=True) or ""


VALID_GIT_FILE_MODES = frozenset({"100644", "100755", "120000", "160000"})
ALLOWED_DIFF_STATUSES = frozenset({"added", "modified", "removed", "renamed", "copied", "changed"})


def _fetch_tree_map(
    repo: str,
    tree_sha: str,
    *,
    recursive: bool,
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> dict[str, tuple[str, str, str]] | str | None:
    key = (tree_sha, recursive)
    if key in tree_cache:
        return tree_cache[key]
    params = {"recursive": "1"} if recursive else None
    res_obj = _expect_dict(request("GET", f"/repos/{repo}/git/trees/{tree_sha}", params=params, allow=(404,)))
    tree_list = _expect_list(res_obj.get("tree")) if res_obj is not None else None
    if res_obj is None or tree_list is None:
        tree_cache[key] = None
        return None
    if res_obj.get("truncated") is True:
        result: dict[str, tuple[str, str, str]] | str | None = "TRUNCATED" if recursive else None
        tree_cache[key] = result
        return result
    entries: dict[str, tuple[str, str, str]] = {}
    for item in tree_list:
        item_obj = _expect_dict(item)
        if item_obj is None:
            continue
        p = _expect_str(item_obj.get("path"), non_empty=True)
        t = _expect_str(item_obj.get("type"))
        m = _expect_str(item_obj.get("mode"))
        s = _expect_sha40(item_obj.get("sha"))
        if (
            p is not None
            and (recursive or ("/" not in p and p not in (".", "..")))
            and t is not None
            and m is not None
            and s is not None
        ):
            entries[p] = (t, m, s)
    tree_cache[key] = entries
    return entries


def _lookup_tree_file_mode(
    repo: str,
    tree_sha: str,
    filepath: str,
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> str:
    if not tree_sha or not filepath:
        return ""
    parts = filepath.split("/")
    if any(not seg or seg in (".", "..") for seg in parts):
        return ""
    flat = _fetch_tree_map(repo, tree_sha, recursive=True, tree_cache=tree_cache)
    flat_map = _expect_dict(flat)
    if flat_map is not None:
        entry = flat_map.get(filepath)
        if entry and entry[0] in ("blob", "commit") and entry[1] in VALID_GIT_FILE_MODES:
            return entry[1]
        return ""
    if flat != "TRUNCATED":
        return ""
    current_tree = tree_sha
    for segment in parts[:-1]:
        node_map = _expect_dict(_fetch_tree_map(repo, current_tree, recursive=False, tree_cache=tree_cache))
        if node_map is None:
            return ""
        sub = node_map.get(segment)
        if not sub or sub[0] != "tree" or sub[1] != "040000":
            return ""
        current_tree = sub[2]
    leaf_map = _expect_dict(_fetch_tree_map(repo, current_tree, recursive=False, tree_cache=tree_cache))
    if leaf_map is None:
        return ""
    leaf = leaf_map.get(parts[-1])
    if leaf and leaf[0] in ("blob", "commit") and leaf[1] in VALID_GIT_FILE_MODES:
        return leaf[1]
    return ""


def _canonical_file_proof(
    entry: dict[str, Any],
    additions: int,
    deletions: int,
    changes: int,
    status: str,
) -> tuple[str, Any] | None:
    patch = entry.get("patch")
    sha_hex = _expect_sha40(entry.get("sha")) or ""
    if (
        patch in (None, "")
        and additions == 0
        and deletions == 0
        and changes == 0
        and sha_hex
        and status == "renamed"
    ):
        return ("rename_sha", sha_hex)
    if (
        patch in (None, "")
        and additions == 0
        and deletions == 0
        and changes == 0
        and sha_hex == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    ):
        return ("empty_blob", sha_hex)
    if complete_patch(entry):
        return ("patch", patch)
    return None


def _canonical_commit_file_entry(
    repo: str,
    entry: Any,
    parent_tree: str,
    commit_tree: str,
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> tuple[Any, ...] | None:
    entry_obj = _expect_dict(entry)
    if entry_obj is None:
        return None
    filename = _expect_str(entry_obj.get("filename"), non_empty=True)
    status = _expect_str(entry_obj.get("status"))
    raw_previous = entry_obj.get("previous_filename")
    previous = "" if raw_previous is None else _expect_str(raw_previous)
    additions = _expect_nonneg_int(entry_obj.get("additions"))
    deletions = _expect_nonneg_int(entry_obj.get("deletions"))
    changes = _expect_nonneg_int(entry_obj.get("changes"))
    if (
        filename is None
        or status is None
        or previous is None
        or additions is None
        or deletions is None
        or changes is None
        or status not in ALLOWED_DIFF_STATUSES
        or changes != additions + deletions
    ):
        return None
    if status == "added":
        old_mode = ""
    else:
        if not parent_tree:
            return None
        old_path = previous if (status in ("renamed", "copied") and previous) else filename
        old_mode = _lookup_tree_file_mode(repo, parent_tree, old_path, tree_cache)
        if not old_mode:
            return None
    if status == "removed":
        new_mode = ""
    else:
        new_mode = _lookup_tree_file_mode(repo, commit_tree, filename, tree_cache)
        if not new_mode:
            return None
    proof = _canonical_file_proof(entry_obj, additions, deletions, changes, status)
    if proof is None:
        return None
    return (filename, previous, status, additions, deletions, changes, old_mode, new_mode, proof)


def _canonical_commit_files(
    repo: str,
    commit_detail: dict[str, Any],
    parent_commit: dict[str, Any] | None,
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> list[tuple[Any, ...]] | None:
    files = _expect_list(commit_detail.get("files"))
    commit_tree = _commit_tree_sha(commit_detail)
    parent_obj = _expect_dict(parent_commit)
    parent_tree = _commit_tree_sha(parent_obj) if parent_obj is not None else ""
    if (
        commit_detail.get("_files_complete") is not _FILES_COMPLETE_TOKEN
        or files is None
        or not (0 < len(files) <= 3000)
        or not commit_tree
    ):
        return None
    normalized: list[tuple[Any, ...]] = []
    covered_paths: set[str] = set()
    for entry in files:
        record = _canonical_commit_file_entry(repo, entry, parent_tree, commit_tree, tree_cache)
        if record is None:
            return None
        covered_paths.add(record[0])
        if record[1]:
            covered_paths.add(record[1])
        normalized.append(record)
    parent_map = (
        {}
        if parent_commit is None
        else (_fetch_tree_map(repo, parent_tree, recursive=True, tree_cache=tree_cache) if parent_tree else None)
    )
    commit_map = _fetch_tree_map(repo, commit_tree, recursive=True, tree_cache=tree_cache)
    if _has_uncovered_tree_diff(
        repo,
        parent_tree,
        commit_tree,
        parent_map,
        commit_map,
        covered_paths,
        tree_cache,
    ):
        return None
    normalized.sort()
    return normalized


def _flat_tree_children(
    flat_map: dict[str, tuple[str, str, str]],
    prefix: str,
) -> dict[str, tuple[str, str, str]]:
    children: dict[str, tuple[str, str, str]] = {}
    for full_path, entry in flat_map.items():
        if not full_path.startswith(prefix):
            continue
        rel = full_path[len(prefix):]
        if not rel:
            continue
        if "/" not in rel:
            if rel not in (".", ".."):
                children[rel] = entry
            continue
        subdir = rel.split("/", 1)[0]
        if subdir and subdir not in (".", "..") and subdir not in children:
            children[subdir] = ("tree", "040000", "")
    return children


def _load_tree_children(
    repo: str,
    tree_map: dict[str, tuple[str, str, str]] | str | None,
    prefix: str,
    tree_sha: str,
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> dict[str, tuple[str, str, str]] | None:
    flat = _expect_dict(tree_map)
    if flat is not None:
        return _flat_tree_children(flat, prefix)
    if not tree_sha:
        return {}
    return _expect_dict(_fetch_tree_map(repo, tree_sha, recursive=False, tree_cache=tree_cache))


def _has_uncovered_tree_diff(
    repo: str,
    parent_tree: str,
    commit_tree: str,
    parent_map: dict[str, tuple[str, str, str]] | str | None,
    commit_map: dict[str, tuple[str, str, str]] | str | None,
    covered_paths: set[str],
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> bool:
    if parent_map is None or commit_map is None:
        return True
    parent_dict = _expect_dict(parent_map)
    commit_dict = _expect_dict(commit_map)
    if parent_dict is not None and commit_dict is not None:
        for path in set(parent_dict) | set(commit_dict):
            p_entry = parent_dict.get(path)
            c_entry = commit_dict.get(path)
            p_file = p_entry if (p_entry and p_entry[0] in ("blob", "commit")) else None
            c_file = c_entry if (c_entry and c_entry[0] in ("blob", "commit")) else None
            if p_file != c_file and path not in covered_paths:
                return True
        return False

    stack: list[tuple[str, str, str]] = [("", parent_tree, commit_tree)]
    seen: set[tuple[str, str, str]] = set()
    visited = 0
    while stack:
        prefix, p_sha, c_sha = stack.pop()
        if (prefix, p_sha, c_sha) in seen:
            continue
        seen.add((prefix, p_sha, c_sha))
        visited += 1
        if visited > 2000:
            return True
        if p_sha and c_sha and p_sha == c_sha:
            continue
        p_children = _load_tree_children(repo, parent_map, prefix, p_sha, tree_cache)
        c_children = _load_tree_children(repo, commit_map, prefix, c_sha, tree_cache)
        if p_children is None or c_children is None:
            return True

        for name in set(p_children) | set(c_children):
            full_path = f"{prefix}{name}"
            p_entry = p_children.get(name)
            c_entry = c_children.get(name)
            p_file = p_entry if (p_entry and p_entry[0] in ("blob", "commit")) else None
            c_file = c_entry if (c_entry and c_entry[0] in ("blob", "commit")) else None
            if p_file != c_file and full_path not in covered_paths:
                return True
            p_is_tree = bool(p_entry and p_entry[0] == "tree")
            c_is_tree = bool(c_entry and c_entry[0] == "tree")
            if (p_is_tree and p_entry[1] != "040000") or (c_is_tree and c_entry[1] != "040000"):
                return True
            if p_is_tree or c_is_tree:
                p_sub = p_entry[2] if p_is_tree else ""
                c_sub = c_entry[2] if c_is_tree else ""
                if p_sub and c_sub and p_sub == c_sub:
                    continue
                stack.append((f"{full_path}/", p_sub, c_sub))
    return False


_FILES_COMPLETE_TOKEN = object()


def _resolve_commit_detail(repo: str, commit: dict[str, Any]) -> dict[str, Any] | None:
    if commit.get("_files_complete") is _FILES_COMPLETE_TOKEN and _expect_list(commit.get("files")) is not None:
        return commit
    sha = _expect_str(commit.get("sha"), non_empty=True)
    if sha is None:
        return None
    base_detail: dict[str, Any] | None = None
    all_files: list[dict[str, Any]] = []
    seen_page_keys: tuple[tuple[str, str, str], ...] | None = None
    for page in range(1, 31):
        detail = _expect_dict(
            request(
                "GET",
                f"/repos/{repo}/commits/{sha}",
                params={"per_page": 100, "page": page},
                allow=(404,),
            )
        )
        chunk = _expect_list(detail.get("files")) if detail is not None else None
        if detail is None or chunk is None:
            return None
        if base_detail is None:
            base_detail = detail
        if not chunk:
            break
        page_keys: list[tuple[str, str, str]] = []
        for item in chunk:
            item_obj = _expect_dict(item)
            if item_obj is None:
                return None
            fn = _expect_str(item_obj.get("filename"), non_empty=True)
            st = _expect_str(item_obj.get("status"), non_empty=True)
            if fn is None or st is None:
                return None
            page_keys.append((fn, st, str(item_obj.get("sha") or "")))
        keys_tuple = tuple(page_keys)
        if page > 1 and keys_tuple == seen_page_keys:
            return None
        seen_page_keys = keys_tuple
        all_files.extend(chunk)
        if len(all_files) > 3000:
            return None
        if len(chunk) < 30:
            break
        if page == 30:
            return None
    if base_detail is None:
        return None
    stats = _expect_dict(base_detail.get("stats"))
    if stats is not None and "total" in stats and stats["total"] is not None:
        total = _expect_int(stats["total"])
        if total is None:
            return None
        total_changes = 0
        for item in all_files:
            ch = _expect_nonneg_int(item.get("changes"))
            if ch is None:
                return None
            total_changes += ch
        if total != total_changes:
            return None
    return {**base_detail, "files": all_files, "_files_complete": _FILES_COMPLETE_TOKEN}


def _rebased_chain_content_matches(
    repo: str,
    step_commits: list[dict[str, Any]],
    pr_commits: list[dict[str, Any]],
    base_parent: str,
    pr_base_parent: str,
    indexed: dict[str, dict[str, Any]] | None = None,
) -> bool:
    if len(step_commits) != len(pr_commits) or not pr_commits:
        return False
    if all(
        (s_sha := _expect_str(s.get("sha"), non_empty=True)) is not None and s_sha == p.get("sha")
        for s, p in zip(step_commits, pr_commits)
    ):
        return True
    if base_parent and pr_base_parent == base_parent:
        tree_pairs = [(_commit_tree_sha(s), _commit_tree_sha(p)) for s, p in zip(step_commits, pr_commits)]
        if all(st and st == pt for st, pt in tree_pairs):
            return True
    step_parent_head = _resolve_commit(repo, base_parent, indexed if indexed is not None else {}) if base_parent else None
    pr_parent_head = _resolve_commit(repo, pr_base_parent, {}) if pr_base_parent else None
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None] = {}
    for index, (step_commit, pr_commit) in enumerate(zip(step_commits, pr_commits)):
        step_detail = _resolve_commit_detail(repo, step_commit)
        pr_detail = _resolve_commit_detail(repo, pr_commit)
        if step_detail is None or pr_detail is None:
            return False
        step_parent = step_parent_head if index == 0 else step_commits[index - 1]
        pr_parent = pr_parent_head if index == 0 else pr_commits[index - 1]
        step_files = _canonical_commit_files(repo, step_detail, step_parent, tree_cache)
        pr_files = _canonical_commit_files(repo, pr_detail, pr_parent, tree_cache)
        if step_files is None or pr_files is None or step_files != pr_files:
            return False
    return True


def _matching_verdicts(
    comments: list[dict[str, Any]],
    repo: str,
    number: Any,
    head: str,
    merge_sha: Any,
    signers: set[str] | None,
) -> list[dict[str, Any]]:
    if not signers:
        return []
    matched: list[dict[str, Any]] = []
    for comment in comments:
        comment_obj = _expect_dict(comment)
        if comment_obj is None:
            continue
        author = _expect_str(_dict_at(comment_obj, "user").get("login"))
        if author is None or author not in signers:
            continue
        body = comment_obj.get("body") or ""
        for match in re.finditer(rf"<!--\s*{VERDICT_MARKER}\s*(\{{[\s\S]*?\}})\s*-->", body):
            try:
                verdict = json.loads(match.group(1))
            except ValueError:
                continue
            verdict_obj = _expect_dict(verdict)
            if verdict_obj is None:
                continue
            if (
                verdict_obj.get("repo") == repo
                and verdict_obj.get("pr") == number
                and verdict_obj.get("head_sha") == head
                and verdict_obj.get("merge_sha") == merge_sha
                and verdict_obj.get("verdict") == "pass"
                and verdict_obj.get("merged") is True
            ):
                matched.append(verdict_obj)
    return matched


def _authenticated_pull_merge_method(
    repo: str,
    pull: dict[str, Any],
    merge_sha: str,
    signers: set[str] | None,
) -> str | None:
    if not signers:
        return None
    number = _expect_int(pull.get("number"))
    head = _expect_str(_dict_at(pull, "head").get("sha"), non_empty=True)
    if number is None or head is None or not merge_sha:
        return None
    comments = paginate(f"/repos/{repo}/issues/{number}/comments")
    for verdict in _matching_verdicts(comments, repo, number, head, merge_sha, signers):
        method = _expect_str(verdict.get("merge_method"), non_empty=True)
        if method is not None:
            return method
    return None


def _is_ancestor_of_base_parent(
    repo: str,
    base_sha: str,
    base_parent: str,
    indexed: dict[str, dict[str, Any]],
) -> bool:
    if not base_sha or not base_parent:
        return False
    target = base_sha.lower()
    current: Any = base_parent
    seen: set[str] = set()
    had_multi_parent = False
    reached_root = False
    while (current_sha := _expect_str(current, non_empty=True)) is not None and current_sha.lower() not in seen:
        lowered = current_sha.lower()
        if lowered == target:
            return True
        seen.add(lowered)
        commit = _expect_dict(indexed.get(current_sha))
        if commit is None:
            break
        parents = []
        for parent in (commit.get("parents") or []):
            parent_obj = _expect_dict(parent)
            parent_sha = _expect_str(parent_obj.get("sha"), non_empty=True) if parent_obj is not None else None
            if parent_sha is not None:
                parents.append(parent_sha)
        if len(parents) > 1:
            had_multi_parent = True
        if not parents:
            reached_root = True
            break
        current = parents[0]
    if reached_root and not had_multi_parent:
        return False
    return _commit_is_ancestor(repo, base_sha, base_parent)


def _single_parent_sha(commit: Any) -> str | None:
    commit_obj = _expect_dict(commit)
    if commit_obj is None:
        return None
    parents = commit_obj.get("parents") or []
    if len(parents) != 1:
        return None
    parent_obj = _expect_dict(parents[0])
    if parent_obj is None:
        return None
    return _expect_str(parent_obj.get("sha"), non_empty=True)


def _fetch_pr_commit_chain(repo: str, number: int, head_sha: str) -> tuple[list[dict[str, Any]], str] | None:
    pr_commits: list[dict[str, Any]] = []
    page = 1
    while True:
        chunk = _expect_list(
            request(
                "GET",
                f"/repos/{repo}/pulls/{number}/commits",
                params={"per_page": 100, "page": page},
                allow=(404,),
            )
        )
        if chunk is None:
            return None
        pr_commits.extend(chunk)
        if len(pr_commits) >= 250:
            return None
        if len(chunk) < 100:
            break
        page += 1
    if len(pr_commits) <= 1 or pr_commits[-1].get("sha") != head_sha:
        return None
    pr_base_parent = ""
    for index, pr_commit in enumerate(pr_commits):
        pr_parent_sha = _single_parent_sha(pr_commit)
        if pr_parent_sha is None:
            return None
        if index == 0:
            pr_base_parent = pr_parent_sha
        elif pr_parent_sha != pr_commits[index - 1].get("sha"):
            return None
    return pr_commits, pr_base_parent


def _collect_rebased_commits(
    repo: str,
    pull: dict[str, Any],
    merge_sha: str,
    indexed: dict[str, dict[str, Any]],
    merge_method: str | None = None,
) -> set[str]:
    if merge_method is not None and merge_method != "rebase":
        return set()
    if pull.get("commits") == 1:
        return set()
    number = _expect_int(pull.get("number"))
    head_sha = _expect_str(_dict_at(pull, "head").get("sha"), non_empty=True)
    base_sha = _expect_str(_dict_at(pull, "base").get("sha"), non_empty=True)
    if number is None or head_sha is None or base_sha is None:
        return set()
    chain = _fetch_pr_commit_chain(repo, number, head_sha)
    if chain is None:
        return set()
    pr_commits, pr_base_parent = chain
    earlier_shas: list[str] = []
    step_commits_rev: list[dict[str, Any]] = []
    step_sha = merge_sha
    base_parent = ""
    for index in range(len(pr_commits) - 1, -1, -1):
        pr_commit = pr_commits[index]
        step_commit = _expect_dict(_resolve_commit(repo, step_sha, indexed) if step_sha else None)
        parent_sha = _single_parent_sha(step_commit)
        if step_commit is None or parent_sha is None:
            return set()
        if not _rebased_commit_matches(step_commit, pr_commit):
            return set()
        step_commits_rev.append(step_commit)
        if index < len(pr_commits) - 1:
            earlier_shas.append(step_sha)
        base_parent = parent_sha
        step_sha = parent_sha
    if not _is_ancestor_of_base_parent(repo, base_sha, base_parent, indexed):
        return set()
    if merge_method != "rebase":
        step_commits_rev.reverse()
        if not _rebased_chain_content_matches(
            repo, step_commits_rev, pr_commits, base_parent, pr_base_parent, indexed
        ):
            return set()
    return set(earlier_shas)


def _expand_rebased_pull(
    repo: str,
    pull: dict[str, Any],
    commit_sha: str,
    indexed: dict[str, dict[str, Any]],
    resolved_methods: dict[int, str],
    rebased_commits: set[str],
    signers: set[str] | None,
    *,
    allow_comment_lookup: bool = False,
) -> None:
    number = _expect_int(pull.get("number"))
    method = resolved_methods.get(number) if number is not None else None
    if allow_comment_lookup and method is None and number is not None:
        found_method = _authenticated_pull_merge_method(repo, pull, commit_sha, signers)
        if found_method is not None:
            resolved_methods[number] = found_method
            method = found_method
    rebased_commits.update(
        _collect_rebased_commits(repo, pull, commit_sha, indexed, merge_method=method)
    )


def _inspect_commit_association(
    repo: str,
    default: str,
    current: str,
    commit: dict[str, Any],
    parents: list[Any],
    merge_shas: set,
    pulls_by_merge_sha: dict[str, dict[str, Any]] | None,
    indexed: dict[str, dict[str, Any]],
    resolved_methods: dict[int, str],
    rebased_commits: set[str],
    acknowledged: dict,
    strict: bool,
    signers: set[str] | None,
) -> str | None:
    if current in merge_shas:
        pull = pulls_by_merge_sha.get(current) if pulls_by_merge_sha else None
        if len(parents) == 1 and pull is not None:
            _expand_rebased_pull(
                repo, pull, current, indexed, resolved_methods, rebased_commits, signers
            )
        return None
    related = request("GET", f"/repos/{repo}/commits/{current}/pulls", allow=(404,)) or []
    matched = [
        p
        for p in related
        if p.get("merged_at")
        and _dict_at(p, "base").get("ref") == default
        and p.get("merge_commit_sha") == current
    ]
    if matched:
        if len(parents) == 1:
            for p in matched:
                _expand_rebased_pull(
                    repo,
                    p,
                    current,
                    indexed,
                    resolved_methods,
                    rebased_commits,
                    signers,
                    allow_comment_lookup=True,
                )
        return None
    subject = (_dict_at(commit, "commit").get("message") or "").splitlines()[0]
    note = str(acknowledged.get(current) or acknowledged.get(current[:7]) or "")
    message = f"{current[:7]} on {default} is not associated with a merged pull request: {subject}"
    if note:
        print(f"note: acknowledged direct push {current[:7]}: {note}")
        return None
    if strict:
        return message
    print(f"warning: {message}")
    return None


def scan_direct_pushes(
    repo: str,
    default: str,
    merge_shas: set,
    acknowledged: dict,
    strict: bool,
    limit: int,
    baseline_sha: str = "",
    listing: list[dict[str, Any]] | None = None,
    pulls_by_merge_sha: dict[str, dict[str, Any]] | None = None,
    pull_methods: dict[int, str] | None = None,
    first_parent: set[str] | None = None,
    signers: set[str] | None = None,
) -> list[str]:
    # Only main's first-parent chain is evidence of a push that bypassed the entry;
    # scanning the raw commit listing both misses chain commits behind a long branch
    # merge and reports side-branch commits that never reached main on their own.
    # Committer dates are attacker-controlled and cannot exclude a direct push, so the
    # walk checks every first-parent commit in the bounded window and stops early
    # only at a trusted baseline SHA. The listing is reverse-chronological over side
    # branches too, so ancestors missing from it are fetched one by one rather than
    # silently ending the walk.
    indexed: dict[str, dict[str, Any]] = {}
    if listing is None:
        listing = request("GET", f"/repos/{repo}/commits",
                          params={"sha": default, "per_page": 100}) or []
    for commit in listing:
        indexed.setdefault(commit["sha"], commit)
    resolved_methods: dict[int, str] = dict(pull_methods or {})
    findings: list[str] = []
    rebased_commits: set[str] = set()
    seen_shas: set[str] = set()
    current, visited, steps = (listing[0]["sha"] if listing else ""), 0, 0
    max_steps = max(limit * 20, 2000)
    while current and visited < limit:
        if current in seen_shas:
            findings.append(
                f"{current[:7]} on {default} forms a commit parent cycle; "
                "the direct-push audit is incomplete"
            )
            break
        seen_shas.add(current)
        if baseline_sha and current.lower() == baseline_sha:
            break
        steps += 1
        if steps > max_steps:
            findings.append(
                f"{current[:7]} on {default} exceeded direct-push traversal limit ({max_steps}); "
                "the direct-push audit is incomplete"
            )
            break
        commit = _resolve_commit(repo, current, indexed)
        if commit is None:
            findings.append(f"{current[:7]} on {default} could not be resolved; "
                            f"the direct-push audit is incomplete")
            break
        parents = [parent.get("sha") for parent in (commit.get("parents") or [])]
        next_sha = parents[0] if parents else ""
        if current not in rebased_commits:
            visited += 1
            finding = _inspect_commit_association(
                repo,
                default,
                current,
                commit,
                parents,
                merge_shas,
                pulls_by_merge_sha,
                indexed,
                resolved_methods,
                rebased_commits,
                acknowledged,
                strict,
                signers,
            )
            if finding is not None:
                findings.append(finding)
        current = next_sha
    return findings


def _load_audit_policy(
    repo: str, default: str, policy_ref: str | None, policy_file: str | None
) -> tuple[dict[str, Any], bool]:
    if policy_file:
        policy = _load_policy_file(policy_file)
        verify_script(repo, default)
        return policy, True
    if policy_ref:
        policy = load_policy(repo, policy_ref)
        verify_script(repo, policy_ref)
        return policy, True
    policy = load_policy(repo, default)
    verify_script(repo, default)
    return policy, False


def _resolve_audit_scope(
    policy: dict[str, Any], strict_direct: bool, trusted_policy: bool
) -> tuple[bool, str, str, set[str], dict[str, Any], int, list[str]]:
    strict = bool(strict_direct or policy.get("audit_strict_direct", True))
    violations: list[str] = []
    raw_since = policy.get("audit_since") or ""
    since = ""
    if raw_since:
        parsed_since = _parse_iso_timestamp(raw_since)
        if parsed_since is None or parsed_since > dt.datetime.now(dt.timezone.utc):
            violations.append("audit_since in policy is invalid or in the future")
        else:
            since = parsed_since.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_baseline = policy.get("audit_baseline_sha")
    baseline_sha = ""
    if raw_baseline is not None and raw_baseline != "":
        parsed_baseline = _expect_sha40(raw_baseline, strip=True)
        if parsed_baseline is None:
            violations.append("audit_baseline_sha in policy is invalid")
        else:
            baseline_sha = parsed_baseline
    ignored = {str(number) for number in policy.get("audit_ignore_prs") or []}
    acknowledged = policy.get("audit_acknowledged_direct") or {}
    direct_limit = int(policy.get("audit_direct_commits") or 40)
    if strict and not trusted_policy:
        since = ""
        baseline_sha = ""
        ignored = set()
        acknowledged = {}
        direct_limit = max(direct_limit, 40)
    return strict, since, baseline_sha, ignored, acknowledged, direct_limit, violations


def _fetch_audited_pulls(repo: str, limit: int, since: str, ignored: set[str]) -> list[dict[str, Any]]:
    eligible: list[dict[str, Any]] = []
    page = 1
    while True:
        chunk = request(
            "GET",
            f"/repos/{repo}/pulls",
            params={
                "state": "closed",
                "sort": "updated",
                "direction": "desc",
                "per_page": 100,
                "page": page,
            },
        )
        if not chunk:
            break
        for pull in chunk:
            if not pull.get("merged_at"):
                continue
            if str(pull["number"]) in ignored:
                continue
            if since and pull["merged_at"] < since:
                continue
            eligible.append(pull)
        if len(chunk) < 100:
            break
        oldest_update = chunk[-1].get("updated_at") or ""
        # Every pull request merged at or after `since` was also updated after
        # it, so nothing on a later page can qualify once this page's oldest
        # update predates the cutoff.
        if since and oldest_update < since:
            break
        if len(eligible) >= limit:
            # The oldest of the current newest `limit` merges is the floor. Once
            # a page's oldest update predates that floor, no later merge can
            # enter the window, even though the API orders by update time.
            floor = sorted(pull["merged_at"] for pull in eligible)[-limit]
            if oldest_update < floor:
                break
        page += 1
    # The API sorts by update time, not merge time; select the latest merges
    # before applying the limit so a stale update cannot consume the window.
    eligible.sort(key=lambda pull: pull["merged_at"], reverse=True)
    return eligible[:limit]


def _audit_pull_verdicts(
    repo: str, audited_pulls: list[dict[str, Any]], signers: set[str]
) -> tuple[int, dict[int, str], list[str]]:
    checked = 0
    pull_methods: dict[int, str] = {}
    violations: list[str] = []
    for pull in audited_pulls:
        number = pull["number"]
        checked += 1
        head = pull["head"]["sha"]
        merge_sha = pull.get("merge_commit_sha")
        comments = paginate(f"/repos/{repo}/issues/{number}/comments")
        matched = _matching_verdicts(comments, repo, number, head, merge_sha, signers)
        if not matched:
            violations.append(f"#{number} merged at {head[:7]} without an authenticated passing verdict")
            continue
        number_int = _expect_int(number)
        if number_int is not None:
            for verdict in matched:
                method = _expect_str(verdict.get("merge_method"))
                if method is not None:
                    pull_methods[number_int] = method
    return checked, pull_methods, violations


def _audit_ancestry_rollbacks(
    repo: str,
    default: str,
    listing: list[dict[str, Any]],
    default_pulls: list[dict[str, Any]],
    baseline_sha: str,
) -> tuple[set[str], bool, list[str]]:
    default_tip = listing[0]["sha"] if listing else ""
    first_parent = _first_parent_shas(listing)
    baseline_verified = False
    violations: list[str] = []
    if not default_tip:
        if baseline_sha or default_pulls:
            violations.append(f"could not resolve {default} tip; rollback audit is incomplete")
        return first_parent, baseline_verified, violations
    if baseline_sha:
        baseline_verified = _commit_is_ancestor(repo, baseline_sha, default_tip, first_parent)
        if not baseline_verified:
            violations.append(
                f"baseline {baseline_sha[:7]} is no longer an ancestor of {default} "
                f"(possible force-push rollback)"
            )
    for pull in default_pulls:
        merge_sha = pull.get("merge_commit_sha")
        if merge_sha and not _commit_is_ancestor(repo, merge_sha, default_tip, first_parent):
            violations.append(
                f"#{pull['number']} merge commit {merge_sha[:7]} is no longer an ancestor of "
                f"{default} (possible force-push rollback)"
            )
    return first_parent, baseline_verified, violations


def audit(
    repo: str,
    limit: int,
    strict_direct: bool,
    policy_ref: str | None = None,
    policy_file: str | None = None,
) -> int:
    info = request("GET", f"/repos/{repo}")
    default = info["default_branch"]
    policy, trusted_policy = _load_audit_policy(repo, default, policy_ref, policy_file)
    signers = _valid_verdict_signers(policy)
    strict, since, baseline_sha, ignored, acknowledged, direct_limit, violations = _resolve_audit_scope(
        policy, strict_direct, trusted_policy
    )
    audited_pulls = _fetch_audited_pulls(repo, limit, since, ignored)
    checked, pull_methods, verdict_violations = _audit_pull_verdicts(repo, audited_pulls, signers)
    violations.extend(verdict_violations)

    listing = request(
        "GET",
        f"/repos/{repo}/commits",
        params={"sha": default, "per_page": 100},
    ) or []
    default_pulls = [
        pull for pull in audited_pulls if _dict_at(pull, "base").get("ref") == default
    ]
    first_parent, baseline_verified, rollback_violations = _audit_ancestry_rollbacks(
        repo, default, listing, default_pulls, baseline_sha
    )
    violations.extend(rollback_violations)
    violations.extend(
        _audit_force_pushes(
            repo,
            default,
            since,
            acknowledged,
            baseline_sha=baseline_sha,
            baseline_verified=baseline_verified,
            strict=strict,
        )
    )
    pulls_by_merge_sha = {
        pull["merge_commit_sha"]: pull
        for pull in default_pulls
        if pull.get("merge_commit_sha")
    }
    merge_shas = set(pulls_by_merge_sha)
    violations.extend(
        scan_direct_pushes(
            repo,
            default,
            merge_shas,
            acknowledged,
            strict,
            direct_limit,
            baseline_sha=baseline_sha,
            listing=listing,
            pulls_by_merge_sha=pulls_by_merge_sha,
            pull_methods=pull_methods,
            first_parent=first_parent,
            signers=signers,
        )
    )
    print(f"audited {checked} merged pull requests since {since or 'the beginning'}")
    if violations:
        for item in violations:
            print(f"violation: {item}")
        return 2
    print("no violations")
    return 0


def default_repo() -> str | None:
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return match.group(1) if match else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge entry gate for private repositories")
    parser.add_argument("--repo", default=default_repo(), help="owner/name; defaults to origin")
    parser.add_argument("--pr", type=int, help="pull request number to judge and merge")
    parser.add_argument("--dry-run", action="store_true", help="print the verdict without merging")
    parser.add_argument("--audit", action="store_true", help="scan recent merges for missing verdicts")
    parser.add_argument("--limit", type=int, default=20, help="merged pull requests to audit")
    parser.add_argument("--strict-direct", action="store_true",
                        help="force the strict direct-push audit even if the policy relaxes it")
    parser.add_argument("--policy-ref", help="trusted git ref for audit policy and script verification")
    parser.add_argument(
        "--policy-file",
        help="trusted local policy JSON file (outside the PR worktree) for --audit or initial --pr bootstrap (when default branch returns 404)",
    )
    args = parser.parse_args()
    if not args.repo:
        parser.error("--repo is required outside a git checkout")
    if args.policy_ref and args.policy_file:
        parser.error("--policy-ref and --policy-file cannot be used together")
    if not args.audit and args.policy_ref:
        parser.error("--policy-ref applies only to --audit")
    try:
        if args.audit:
            return audit(
                args.repo,
                args.limit,
                args.strict_direct,
                policy_ref=args.policy_ref,
                policy_file=args.policy_file,
            )
        if not args.pr:
            parser.error("--pr is required unless --audit is used")
        verdict, reasons = evaluate(args.repo, args.pr, policy_file=args.policy_file)
        print(json.dumps(verdict, indent=2, ensure_ascii=False))
        if reasons:
            return 2
        if args.dry_run:
            return 0
        merge(args.repo, verdict, policy_file=args.policy_file)
        print(f"merged #{args.pr} at {verdict['head_sha'][:7]}")
        return 0
    except Refusal as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except ApiError as exc:
        print(f"error: {diagnostic(exc)}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
