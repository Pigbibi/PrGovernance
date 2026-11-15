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
from typing import Any

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
ALL_REVIEW_PROVIDERS = {"codex", "claude", "cursor"}
REVIEWER_PROVIDERS: dict[str, tuple[str, tuple[int, ...]]] = {
    "chatgpt-codex-connector": ("codex", (0, 1, 2)),
    "chatgpt-codex-connector[bot]": ("codex", (0, 1, 2)),
    "claude[bot]": ("claude", (0,)),
    "cursor[bot]": ("cursor", (0,)),
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
    re.compile(r"\.(?:tf|tfvars)$"),
)
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
    except (OSError, ValueError) as exc:
        raise Refusal(f"Cannot read policy file {policy_file}: {exc}") from exc
    if not isinstance(policy, dict):
        raise Refusal(f"Policy file {policy_file} must contain a JSON object")
    policy["_sha256"] = hashlib.sha256(raw).hexdigest()
    policy["_source"] = f"file:{policy_file}"
    return policy


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
    if not isinstance(policy, dict):
        raise Refusal(f"governance/policy.json on {ref} must contain a JSON object")
    policy["_sha256"] = hashlib.sha256(raw).hexdigest()
    policy["_source"] = ref
    return policy


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
    values = policy.get("action_files")
    return set(values) if isinstance(values, list) else set()


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
    return any(
        isinstance(prefix, str)
        and bool(prefix)
        and (path.startswith(prefix) or candidate.startswith(normalized(prefix)))
        for prefix in extra
    )


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
    patch = file.get("patch")
    if not isinstance(patch, str):
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
    return "T1", False


def scan_secrets(files: list[dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for file in files:
        patch = file.get("patch")
        if not isinstance(patch, str):
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
    patch = file.get("patch")
    additions = file.get("additions")
    deletions = file.get("deletions")
    if (
        not isinstance(patch, str)
        or isinstance(additions, bool)
        or not isinstance(additions, int)
        or additions < 0
        or isinstance(deletions, bool)
        or not isinstance(deletions, int)
        or deletions < 0
    ):
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


def dependabot_head(
    repo: str,
    number: int,
    head: str | None = None,
    comparison: dict[str, Any] | None = None,
) -> bool:
    if isinstance(comparison, dict) and "commits" in comparison:
        commits = comparison.get("commits")
        total = comparison.get("total_commits")
        if not isinstance(commits, list) or not commits or len(commits) >= 250:
            return False
        if total is not None and (
            isinstance(total, bool) or not isinstance(total, int) or total != len(commits)
        ):
            return False
    else:
        commits = paginate(f"/repos/{repo}/pulls/{number}/commits")
        if not commits or len(commits) >= 250:
            return False
    if head is not None and (not isinstance(commits[-1], dict) or commits[-1].get("sha") != head):
        return False
    return all(
        isinstance(commit, dict)
        and (commit.get("author") or {}).get("login") == "dependabot[bot]"
        and (commit.get("committer") or {}).get("login") == "web-flow"
        and (commit.get("commit") or {}).get("verification", {}).get("verified") is True
        for commit in commits
    )


def _parse_review_payload(marker_index: int, raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw)
    except (ValueError, AttributeError):
        return None
    if marker_index == 2:
        return payload.get("code_review") if isinstance(payload, dict) else None
    if isinstance(payload, dict):
        review = payload.get("review")
        return review if isinstance(review, dict) else None
    return None


_EPOCH_MIN = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
_EPOCH_MAX = dt.datetime.max.replace(tzinfo=dt.timezone.utc)


def _base_change_cutoff(timeline: list[dict[str, Any]] | None) -> dt.datetime | None:
    if not timeline:
        return None
    latest: dt.datetime | None = None
    for event in timeline:
        if not isinstance(event, dict) or event.get("event") != "base_ref_changed":
            continue
        ts = _parse_iso_timestamp(event.get("created_at"))
        if ts is None:
            return _EPOCH_MAX
        if latest is None or ts > latest:
            latest = ts
    return latest


def _parse_iso_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _receipt_unresolved(review: dict[str, Any]) -> bool | None:
    has_flag: bool | None = None
    count_flag: bool | None = None
    if "has_unresolved_findings" in review:
        val = review.get("has_unresolved_findings")
        if not isinstance(val, bool):
            return None
        has_flag = val
    if "unresolved_findings" in review:
        u = review.get("unresolved_findings")
        if isinstance(u, bool):
            count_flag = u
        elif isinstance(u, int) and not isinstance(u, bool) and u >= 0:
            count_flag = u > 0
        else:
            return None
    if has_flag is not None and count_flag is not None:
        if has_flag != count_flag:
            return None
        return has_flag
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
    on_head = review.get("commit_sha") == head
    if "provider" in review:
        declared = review.get("provider")
        if not isinstance(declared, str) or declared.strip().lower() != login_provider:
            return (
                "failure",
                f"AI review receipt provider does not match comment author {login_provider}",
                on_head,
                False,
            )
    status = review.get("status")
    if status != "completed":
        label = status if isinstance(status, str) and status.strip() else "not finished"
        return "pending", f"AI review {label}", on_head, True
    if not on_head:
        return "failure", "AI review covers another commit, not this head", False, True
    unresolved = _receipt_unresolved(review)
    if unresolved is True:
        return "failure", "AI review still has unresolved findings on this head", True, True
    if unresolved is None:
        return "failure", "AI review findings state is not reported", True, True
    raw_coverage = review.get("coverage")
    if marker_index in (0, 1):
        if not isinstance(raw_coverage, str) or raw_coverage.strip().lower() not in COMPLETE_COVERAGE:
            return "failure", "AI review coverage is incomplete", True, True
    elif raw_coverage is not None:
        if not isinstance(raw_coverage, str) or raw_coverage.strip().lower() not in COMPLETE_COVERAGE:
            return "failure", "AI review coverage is incomplete", True, True
    return "success", f"{login_provider} reviewed this head with no unresolved findings", True, True


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
    # Track the latest receipt per allowed provider, preferring current-head or
    # unparseable receipts (`on_head is not False`) over delayed stale-commit
    # receipts so a later off-head comment cannot mask current-head findings.
    latest_by_provider: dict[
        str,
        tuple[int, dt.datetime, str, int, int, str, str, bool | None, bool],
    ] = {}
    for seq_idx, comment in enumerate(comments):
        login = (comment.get("user") or {}).get("login", "")
        binding = REVIEWER_PROVIDERS.get(login)
        if not binding:
            continue
        login_provider, allowed_indices = binding
        if login_provider not in active:
            continue
        body = comment.get("body") or ""
        matches = _extract_receipt_markers(body)
        if not matches:
            continue
        updated_at = comment.get("updated_at") or comment.get("created_at") or ""
        comment_id = comment.get("id")
        cid = comment_id if isinstance(comment_id, int) and not isinstance(comment_id, bool) else 0
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
        head_rank = 1 if on_head is not False else 0
        candidate = (
            head_rank,
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
        if prev is None or candidate[:5] > prev[:5]:
            latest_by_provider[login_provider] = candidate
    if not latest_by_provider:
        return "pending", "No AI review receipt on this pull request"

    judged = [
        (
            (parsed_ts, updated_at, cid, seq_idx),
            (parsed_ts, updated_at),
            login_provider,
            state,
            note,
            on_head,
            provider_ok,
        )
        for login_provider, (
            _head_rank,
            parsed_ts,
            updated_at,
            cid,
            seq_idx,
            state,
            note,
            on_head,
            provider_ok,
        ) in latest_by_provider.items()
    ]

    judged.sort(key=lambda entry: entry[0], reverse=True)
    passing_head = [e for e in judged if e[5] is True and e[3] == "success"]
    failing_head = [e for e in judged if e[5] is True and e[3] in ("error", "failure")]
    pending_head = [e for e in judged if e[5] is True and e[3] == "pending"]

    if passing_head:
        max_pass_ts = max(e[1] for e in passing_head)
        for entry in judged:
            if entry[5] is None and entry[1] >= max_pass_ts:
                return entry[3], entry[4]
        for entry in judged:
            if not entry[6] and entry[5] is not None and entry[1] >= max_pass_ts:
                return entry[3], entry[4]
        if failing_head:
            return failing_head[0][3], failing_head[0][4]
        if pending_head:
            return pending_head[0][3], pending_head[0][4]
        return passing_head[0][3], passing_head[0][4]

    if failing_head:
        return failing_head[0][3], failing_head[0][4]
    if pending_head:
        return pending_head[0][3], pending_head[0][4]
    return judged[0][3], judged[0][4]


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
    configured = policy.get("ai_review_providers")
    if isinstance(configured, list):
        return {
            p.strip().lower()
            for p in configured
            if isinstance(p, str) and p.strip().lower() in ALL_REVIEW_PROVIDERS
        }
    return set()


_UNSET = object()


def _clean_logins(configured: Any) -> set[str]:
    if not isinstance(configured, list):
        return set()
    return {login.strip() for login in configured if isinstance(login, str) and login.strip()}


def policy_agent_logins(policy: dict[str, Any] | None) -> set[str]:
    if not isinstance(policy, dict):
        return set()
    configured = policy.get("agent_logins")
    if not isinstance(configured, list):
        configured = policy.get("approved_agent_logins")
    return _clean_logins(configured)


def _valid_verdict_signers(policy: dict[str, Any] | None) -> set[str]:
    """Return GitHub logins accepted by audit() as merge verdict signers."""
    if not isinstance(policy, dict):
        return set()
    signers = _clean_logins(policy.get("verdict_signers"))
    owner = policy.get("owner_login")
    if isinstance(owner, str) and owner.strip():
        signers.add(owner.strip())
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
    caller_login = caller.get("login") if isinstance(caller, dict) else None
    if not isinstance(caller_login, str) or not caller_login.strip():
        raise Refusal("Cannot identify authenticated GitHub caller; refusing merge")
    caller_login = caller_login.strip()
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
    actor_login = (event.get("actor") or {}).get("login") or ""
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
        if chunk is None or not isinstance(chunk, list):
            return None
        entries.extend(chunk)
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


def live_label(
    repo: str,
    number: int,
    owner: str,
    pull: dict[str, Any] | None = None,
    agent_logins: set[str] | None = None,
    timeline: list[dict[str, Any]] | None = None,
) -> str | None:
    if pull is None:
        events = paginate(f"/repos/{repo}/issues/{number}/events")
        latest: dict[str, dict[str, Any]] = {}
        for event in events:
            name = (event.get("label") or {}).get("name")
            if event.get("event") in ("labeled", "unlabeled") and name in ("owner-approved", "agent-approved"):
                latest[name] = event
        for name in ("owner-approved", "agent-approved"):
            event = latest.get(name)
            if event and _valid_clearing_actor(name, event, owner, agent_logins):
                return name
        return None

    present = {(lbl.get("name") or "") for lbl in (pull.get("labels") or [])}
    if not (present & {"owner-approved", "agent-approved"}):
        return None
    head_info = pull.get("head") or {}
    head = head_info.get("sha") or ""
    if not head:
        return None
    if timeline is None:
        timeline = paginate(f"/repos/{repo}/issues/{number}/timeline")
    latest = {}
    reset_events = ("committed", "head_ref_force_pushed", "head_ref_restored", "reopened", "base_ref_changed")
    base_changed_at = _base_change_cutoff(timeline)
    for event in timeline:
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        if kind in reset_events:
            latest.clear()
            continue
        name = (event.get("label") or {}).get("name")
        if kind in ("labeled", "unlabeled") and name in ("owner-approved", "agent-approved"):
            latest[name] = event

    statuses: list[dict[str, Any]] | None = None
    activities: Any = _UNSET
    head_repo = ((head_info.get("repo") or {}).get("full_name") or "")
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
        event_id = event.get("id")
        if event_id is not None and not isinstance(event_id, bool):
            expected = f"{name} for PR {number} at event {event_id} on this head"
            for s in statuses:
                if (
                    s.get("context") == "clearing-label"
                    and s.get("state") == "success"
                    and (s.get("creator") or {}).get("login") == ACTIONS_BOT
                    and s.get("description") == expected
                ):
                    if base_changed_at is not None:
                        status_ts = _parse_iso_timestamp(s.get("updated_at") or s.get("created_at"))
                        if status_ts is None or status_ts < base_changed_at:
                            continue
                    return name
        activity_repo = head_repo or ""
        if not activity_repo or not head_ref or event_ts is None:
            continue
        if activities is _UNSET:
            activities = branch_activities(activity_repo, head_ref)
        if not activities:
            continue
        timed_entries: list[tuple[dt.datetime, dict[str, Any]]] = []
        valid_entries = True
        for entry in activities:
            if not isinstance(entry, dict) or not isinstance(entry.get("activity_type"), str) or not entry.get("activity_type"):
                valid_entries = False
                break
            ts = _parse_iso_timestamp(entry.get("timestamp"))
            if ts is None:
                valid_entries = False
                break
            timed_entries.append((ts, entry))
        if not valid_entries or not timed_entries:
            continue
        newest_ts, newest = max(timed_entries, key=lambda pair: pair[0])
        if newest.get("activity_type") != "branch_deletion" and newest.get("after") == head and event_ts >= newest_ts:
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
    return [name for name in names or [] if isinstance(name, str) and name]


def applicable_contexts(
    policy: dict[str, Any], verified_dependabot: bool, files: list[dict[str, Any]]
) -> list[str]:
    required = required_contexts(policy, verified_dependabot)
    skipped = policy.get("ci_skipped_checks")
    if not isinstance(skipped, dict):
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
        if context not in required or not isinstance(patterns, list):
            continue
        globs = [pattern for pattern in patterns if isinstance(pattern, str)]
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
            data = request("GET", f"/repos/{repo}/git/trees/{current_sha}", allow=(404,))
            if not isinstance(data, dict) or not isinstance(data.get("tree"), list):
                tree_cache[current_sha] = None
                return False, False
            tree_cache[current_sha] = {
                e.get("path"): e
                for e in data["tree"]
                if isinstance(e, dict) and isinstance(e.get("path"), str)
            }
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
    checked = [
        f.get("filename")
        for f in files
        if f.get("status") != "removed" and isinstance(f.get("filename"), str) and f.get("filename")
    ]
    if not checked:
        return [], True
    tree = request(
        "GET",
        f"/repos/{repo}/git/trees/{head}",
        params={"recursive": "1"},
        allow=(404,),
    )
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        return [], False
    modes = {
        e.get("path"): e.get("mode")
        for e in tree["tree"]
        if isinstance(e, dict) and isinstance(e.get("path"), str)
    }
    flagged: list[str] = []
    tree_cache: dict[str, dict[str, dict[str, Any]] | None] = {}
    truncated = bool(tree.get("truncated"))
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


def evaluate(repo: str, number: int, policy_file: str | None = None) -> tuple[dict[str, Any], list[str]]:
    pull = request("GET", f"/repos/{repo}/pulls/{number}")
    if pull.get("state") != "open":
        raise Refusal(f"Pull request #{number} is {pull.get('state')}, not open")
    if pull.get("draft"):
        raise Refusal(f"Pull request #{number} is a draft; mark it ready before merging")
    head = pull["head"]["sha"]
    base_ref = pull["base"]["ref"]
    policy_ref = request("GET", f"/repos/{repo}")["default_branch"]
    if policy_file:
        policy = _load_bootstrap_policy_file(repo, policy_ref, policy_file)
        bootstrap = True
        print(
            f"warning: using trusted --policy-file ({policy_file}) instead of {policy_ref} (bootstrap)",
            file=sys.stderr,
        )
    else:
        policy = load_policy(repo, policy_ref)
        bootstrap = False
    verify_script(repo, policy_ref)
    contains_base, base_head, comparison = head_comparison(repo, base_ref, head)
    raw_files = comparison.get("files") if isinstance(comparison, dict) else None
    valid_files = isinstance(raw_files, list) and all(isinstance(item, dict) for item in raw_files)
    files = raw_files if valid_files else []
    reasons: list[str] = []
    if not valid_files or len(files) >= 300 or len(files) != pull.get("changed_files"):
        reasons.append("Changed-file list is incomplete; refuse to judge a partial diff")
    if not contains_base:
        reasons.append("Base branch advanced since this head was built; update the branch first")
    if shared_head(repo, number, head):
        reasons.append("Another open pull request shares this head; verdicts would collide")
    symlinks, tree_ok = symlink_entries(repo, head, files)
    symlink_set = set(symlinks)
    if symlinks:
        reasons.append(
            "Symlink entries are not allowed in pull requests: " + ", ".join(sorted(symlinks)[:5])
        )
    if not tree_ok:
        reasons.append("Cannot verify Git tree modes for changed files")
    for file in files:
        if file.get("filename") in symlink_set:
            continue
        if complete_patch(file) or file.get("changes") != 0:
            continue
        if Path(file.get("filename") or "").suffix.lower() in BINARY_EXTENSIONS:
            continue
        if not file.get("sha"):
            continue
        blob = request("GET", f"/repos/{repo}/git/blobs/{file['sha']}", allow=(404,))
        file["_size"] = (blob or {}).get("size")
    verified_dependabot = (
        (pull.get("user") or {}).get("login") == "dependabot[bot]"
        and dependabot_head(repo, number, head=head, comparison=comparison)
    )
    extra = tuple(policy.get("extra_protected_paths") or ())
    tier, fast_path = classify(files, verified_dependabot, base_action_files(repo, policy_ref), extra)
    if symlinks or not tree_ok:
        tier = "T2"
        fast_path = False
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
    hits = scan_secrets(files)
    if hits:
        reasons.append("Possible secret in the diff: " + "; ".join(sorted(set(hits))[:5]))
    unscanned = [file.get("filename") for file in files if not complete_patch(file)]
    unscannable = unscanned_text(files)
    if unscannable:
        reasons.append("Cannot scan text changes without a diff: " + ", ".join(unscannable[:5]))
    required: list[str] = []
    if policy.get("require_checks", True):
        required = applicable_contexts(policy, verified_dependabot, files)
        if not required:
            reasons.append("CI is required but no applicable context remains")
            checks = "missing"
            checks_note = ""
        else:
            missing, unsettled, pending, failing = check_results(repo, head, required)
            if missing:
                reasons.append("CI did not report required contexts: " + ", ".join(missing[:5]))
            if unsettled:
                reasons.append("CI has not succeeded: " + ", ".join(unsettled[:5]))
            if pending:
                reasons.append("CI is still running: " + ", ".join(pending[:5]))
            if failing:
                reasons.append("CI is not successful: " + ", ".join(failing[:5]))
            checks = "pending" if pending and not (missing or unsettled or failing) else (
                "failure" if missing or unsettled or failing else "success"
            )
            checks_note = (
                "The merge entry is not on the default branch yet; the contexts come from "
                "the trusted --policy-file"
                if bootstrap else ""
            )
    else:
        checks = "skipped"
        checks_note = policy.get("checks_disabled_reason") or "not required by policy"
        if bootstrap:
            checks_note += " (policy read from --policy-file; the entry is not installed yet)"
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
    indexed = {
        commit["sha"]: commit
        for commit in listing
        if isinstance(commit, dict) and isinstance(commit.get("sha"), str)
    }
    reachable: set[str] = set()
    current = listing[0].get("sha") if listing and isinstance(listing[0], dict) else ""
    while isinstance(current, str) and current and current.lower() not in reachable:
        reachable.add(current.lower())
        commit = indexed.get(current)
        if not commit:
            break
        parents = [
            parent.get("sha")
            for parent in (commit.get("parents") or [])
            if isinstance(parent, dict)
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
    comparison = request(
        "GET",
        f"/repos/{repo}/compare/{ancestor}...{tip}",
        allow=(404, 422),
    )
    if not isinstance(comparison, dict):
        return False
    merge_base = (comparison.get("merge_base_commit") or {}).get("sha")
    if not isinstance(merge_base, str) or merge_base.lower() != lowered:
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
        if not isinstance(entry, dict) or entry.get("activity_type") != "force_push":
            continue
        entry_ref = entry.get("ref")
        if entry_ref is not None and entry_ref != expected_ref:
            continue
        entry_ts = _parse_iso_timestamp(entry.get("timestamp"))
        if since_dt is not None and entry_ts is not None and entry_ts < since_dt:
            continue
        entry_id = entry.get("id")
        id_key = (
            str(entry_id)
            if entry_id is not None and not isinstance(entry_id, bool)
            else ""
        )
        note = ""
        if id_key:
            note = str(acknowledged.get(f"activity:{id_key}") or acknowledged.get(id_key) or "")
        if note:
            print(f"note: acknowledged force push on {default} ({id_key}): {note}")
            continue
        before = str(entry.get("before") or "")
        after = str(entry.get("after") or "")
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
    step_sha = step_commit.get("sha")
    pr_sha = pr_commit.get("sha")
    if isinstance(step_sha, str) and isinstance(pr_sha, str) and step_sha and step_sha == pr_sha:
        return True
    step_meta = step_commit.get("commit")
    pr_meta = pr_commit.get("commit")
    if not isinstance(step_meta, dict) or not isinstance(pr_meta, dict):
        return False
    step_message = step_meta.get("message")
    pr_message = pr_meta.get("message")
    if (
        not isinstance(step_message, str)
        or not isinstance(pr_message, str)
        or not pr_message
        or step_message != pr_message
    ):
        return False
    step_author = step_meta.get("author")
    pr_author = pr_meta.get("author")
    if not isinstance(step_author, dict) or not isinstance(pr_author, dict):
        return False
    pr_email = pr_author.get("email")
    if not isinstance(pr_email, str) or not pr_email or step_author.get("email") != pr_email:
        return False
    pr_date = pr_author.get("date")
    if not isinstance(pr_date, str) or not pr_date or step_author.get("date") != pr_date:
        return False
    pr_name = pr_author.get("name")
    if isinstance(pr_name, str) and pr_name and step_author.get("name") != pr_name:
        return False
    return True


def _commit_tree_sha(commit: dict[str, Any]) -> str:
    tree_sha = ((commit.get("commit") or {}).get("tree") or {}).get("sha")
    if isinstance(tree_sha, str):
        lowered = tree_sha.strip().lower()
        if re.fullmatch(r"[0-9a-f]{40}", lowered):
            return lowered
    return ""


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
    res = request("GET", f"/repos/{repo}/git/trees/{tree_sha}", params=params, allow=(404,))
    if not isinstance(res, dict) or not isinstance(res.get("tree"), list):
        tree_cache[key] = None
        return None
    if res.get("truncated") is True:
        result: dict[str, tuple[str, str, str]] | str | None = "TRUNCATED" if recursive else None
        tree_cache[key] = result
        return result
    path_key = "path"
    entries: dict[str, tuple[str, str, str]] = {}
    for item in res["tree"]:
        if not isinstance(item, dict):
            continue
        p = item.get(path_key)
        t = item.get("type")
        m = item.get("mode")
        s = item.get("sha")
        if (
            isinstance(p, str)
            and p
            and (recursive or ("/" not in p and p not in (".", "..")))
            and isinstance(t, str)
            and isinstance(m, str)
            and isinstance(s, str)
            and re.fullmatch(r"[0-9a-f]{40}", s.lower())
        ):
            entries[p] = (t, m, s.lower())
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
    if isinstance(flat, dict):
        entry = flat.get(filepath)
        if entry and entry[0] in ("blob", "commit") and entry[1] in VALID_GIT_FILE_MODES:
            return entry[1]
        return ""
    if flat != "TRUNCATED":
        return ""
    current_tree = tree_sha
    for segment in parts[:-1]:
        node_map = _fetch_tree_map(repo, current_tree, recursive=False, tree_cache=tree_cache)
        if not isinstance(node_map, dict):
            return ""
        sub = node_map.get(segment)
        if not sub or sub[0] != "tree" or sub[1] != "040000":
            return ""
        current_tree = sub[2]
    leaf_map = _fetch_tree_map(repo, current_tree, recursive=False, tree_cache=tree_cache)
    if not isinstance(leaf_map, dict):
        return ""
    leaf = leaf_map.get(parts[-1])
    if leaf and leaf[0] in ("blob", "commit") and leaf[1] in VALID_GIT_FILE_MODES:
        return leaf[1]
    return ""


def _canonical_commit_files(
    repo: str,
    commit_detail: dict[str, Any],
    parent_commit: dict[str, Any] | None,
    tree_cache: dict[tuple[str, bool], dict[str, tuple[str, str, str]] | str | None],
) -> list[tuple[Any, ...]] | None:
    files = commit_detail.get("files")
    commit_tree = _commit_tree_sha(commit_detail)
    parent_tree = _commit_tree_sha(parent_commit) if isinstance(parent_commit, dict) else ""
    if (
        commit_detail.get("_files_complete") is not _FILES_COMPLETE_TOKEN
        or not isinstance(files, list)
        or not (0 < len(files) <= 3000)
        or not commit_tree
    ):
        return None
    normalized: list[tuple[Any, ...]] = []
    covered_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            return None
        filename = entry.get("filename")
        status = entry.get("status")
        raw_previous = entry.get("previous_filename")
        if raw_previous is None:
            previous = ""
        elif isinstance(raw_previous, str):
            previous = raw_previous
        else:
            return None
        additions = entry.get("additions")
        deletions = entry.get("deletions")
        changes = entry.get("changes")
        if (
            not isinstance(filename, str)
            or not filename
            or not isinstance(status, str)
            or status not in ALLOWED_DIFF_STATUSES
            or not isinstance(additions, int)
            or isinstance(additions, bool)
            or additions < 0
            or not isinstance(deletions, int)
            or isinstance(deletions, bool)
            or deletions < 0
            or not isinstance(changes, int)
            or isinstance(changes, bool)
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
        patch = entry.get("patch")
        sha = entry.get("sha")
        sha_hex = sha.lower() if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha.lower()) else ""
        if (
            patch in (None, "")
            and additions == 0
            and deletions == 0
            and changes == 0
            and sha_hex
            and status == "renamed"
        ):
            proof: tuple[str, str] = ("rename_sha", sha_hex)
        elif (
            patch in (None, "")
            and additions == 0
            and deletions == 0
            and changes == 0
            and sha_hex == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        ):
            proof = ("empty_blob", sha_hex)
        elif complete_patch(entry):
            proof = ("patch", patch)
        else:
            return None
        covered_paths.add(filename)
        if isinstance(previous, str) and previous:
            covered_paths.add(previous)
        normalized.append((filename, previous, status, additions, deletions, changes, old_mode, new_mode, proof))
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
    if isinstance(parent_map, dict) and isinstance(commit_map, dict):
        for path in set(parent_map) | set(commit_map):
            p_entry = parent_map.get(path)
            c_entry = commit_map.get(path)
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
        if isinstance(parent_map, dict):
            p_children = _flat_tree_children(parent_map, prefix)
        elif not p_sha:
            p_children = {}
        else:
            loaded = _fetch_tree_map(repo, p_sha, recursive=False, tree_cache=tree_cache)
            if not isinstance(loaded, dict):
                return True
            p_children = loaded

        if isinstance(commit_map, dict):
            c_children = _flat_tree_children(commit_map, prefix)
        elif not c_sha:
            c_children = {}
        else:
            loaded = _fetch_tree_map(repo, c_sha, recursive=False, tree_cache=tree_cache)
            if not isinstance(loaded, dict):
                return True
            c_children = loaded

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
    if commit.get("_files_complete") is _FILES_COMPLETE_TOKEN and isinstance(commit.get("files"), list):
        return commit
    sha = commit.get("sha")
    if not isinstance(sha, str) or not sha:
        return None
    base_detail: dict[str, Any] | None = None
    all_files: list[dict[str, Any]] = []
    seen_page_keys: tuple[tuple[str, str, str], ...] | None = None
    for page in range(1, 31):
        detail = request(
            "GET",
            f"/repos/{repo}/commits/{sha}",
            params={"per_page": 100, "page": page},
            allow=(404,),
        )
        if not isinstance(detail, dict):
            return None
        chunk = detail.get("files")
        if not isinstance(chunk, list):
            return None
        if base_detail is None:
            base_detail = detail
        if not chunk:
            break
        page_keys: list[tuple[str, str, str]] = []
        for item in chunk:
            if not isinstance(item, dict):
                return None
            fn = item.get("filename")
            st = item.get("status")
            if not isinstance(fn, str) or not fn or not isinstance(st, str) or not st:
                return None
            page_keys.append((fn, st, str(item.get("sha") or "")))
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
    stats = base_detail.get("stats")
    if isinstance(stats, dict) and "total" in stats and stats["total"] is not None:
        total = stats["total"]
        if not isinstance(total, int) or isinstance(total, bool):
            return None
        total_changes = 0
        for item in all_files:
            ch = item.get("changes")
            if not isinstance(ch, int) or isinstance(ch, bool) or ch < 0:
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
        isinstance(s.get("sha"), str) and s.get("sha") and s.get("sha") == p.get("sha")
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


def _authenticated_pull_merge_method(
    repo: str,
    pull: dict[str, Any],
    merge_sha: str,
    signers: set[str] | None,
) -> str | None:
    if not signers:
        return None
    number = pull.get("number")
    head = (pull.get("head") or {}).get("sha")
    if (
        not isinstance(number, int)
        or isinstance(number, bool)
        or not isinstance(head, str)
        or not head
        or not merge_sha
    ):
        return None
    comments = paginate(f"/repos/{repo}/issues/{number}/comments")
    for comment in comments:
        author = (comment.get("user") or {}).get("login")
        if not isinstance(author, str) or author not in signers:
            continue
        for match in re.finditer(rf"<!--\s*{VERDICT_MARKER}\s*(\{{[\s\S]*?\}})\s*-->", comment.get("body") or ""):
            try:
                verdict = json.loads(match.group(1))
            except ValueError:
                continue
            if (
                verdict.get("repo") == repo
                and verdict.get("pr") == number
                and verdict.get("head_sha") == head
                and verdict.get("merge_sha") == merge_sha
                and verdict.get("verdict") == "pass"
                and verdict.get("merged") is True
            ):
                method = verdict.get("merge_method")
                if isinstance(method, str) and method:
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
    current = base_parent
    seen: set[str] = set()
    had_multi_parent = False
    reached_root = False
    while isinstance(current, str) and current and current.lower() not in seen:
        lowered = current.lower()
        if lowered == target:
            return True
        seen.add(lowered)
        commit = indexed.get(current)
        if not isinstance(commit, dict):
            break
        parents = [
            p.get("sha")
            for p in (commit.get("parents") or [])
            if isinstance(p, dict) and isinstance(p.get("sha"), str) and p.get("sha")
        ]
        if len(parents) > 1:
            had_multi_parent = True
        if not parents:
            reached_root = True
            break
        current = parents[0]
    if reached_root and not had_multi_parent:
        return False
    return _commit_is_ancestor(repo, base_sha, base_parent)


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
    number = pull.get("number")
    head_sha = (pull.get("head") or {}).get("sha")
    base_sha = (pull.get("base") or {}).get("sha")
    if (
        not isinstance(number, int)
        or isinstance(number, bool)
        or not isinstance(head_sha, str)
        or not head_sha
        or not isinstance(base_sha, str)
        or not base_sha
    ):
        return set()
    pr_commits: list[dict[str, Any]] = []
    page = 1
    while True:
        chunk = request(
            "GET",
            f"/repos/{repo}/pulls/{number}/commits",
            params={"per_page": 100, "page": page},
            allow=(404,),
        )
        if not isinstance(chunk, list):
            return set()
        pr_commits.extend(chunk)
        if len(pr_commits) >= 250:
            return set()
        if len(chunk) < 100:
            break
        page += 1
    if len(pr_commits) <= 1 or pr_commits[-1].get("sha") != head_sha:
        return set()
    pr_base_parent = ""
    for index, pr_commit in enumerate(pr_commits):
        if not isinstance(pr_commit, dict):
            return set()
        pr_parents = pr_commit.get("parents") or []
        if len(pr_parents) != 1 or not isinstance(pr_parents[0], dict):
            return set()
        pr_parent_sha = pr_parents[0].get("sha")
        if not isinstance(pr_parent_sha, str) or not pr_parent_sha:
            return set()
        if index == 0:
            pr_base_parent = pr_parent_sha
        elif pr_parent_sha != pr_commits[index - 1].get("sha"):
            return set()
    earlier_shas: list[str] = []
    step_commits_rev: list[dict[str, Any]] = []
    step_sha = merge_sha
    base_parent = ""
    for index in range(len(pr_commits) - 1, -1, -1):
        pr_commit = pr_commits[index]
        step_commit = _resolve_commit(repo, step_sha, indexed) if step_sha else None
        if not isinstance(step_commit, dict):
            return set()
        raw_parents = step_commit.get("parents") or []
        if len(raw_parents) != 1 or not isinstance(raw_parents[0], dict):
            return set()
        parent_sha = raw_parents[0].get("sha")
        if not isinstance(parent_sha, str) or not parent_sha:
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
    current, visited = (listing[0]["sha"] if listing else ""), 0
    while current and visited < limit:
        if baseline_sha and current.lower() == baseline_sha:
            break
        commit = _resolve_commit(repo, current, indexed)
        if commit is None:
            findings.append(f"{current[:7]} on {default} could not be resolved; "
                            f"the direct-push audit is incomplete")
            break
        parents = [parent.get("sha") for parent in (commit.get("parents") or [])]
        next_sha = parents[0] if parents else ""
        visited += 1
        if current in rebased_commits:
            current = next_sha
            continue
        pull = pulls_by_merge_sha.get(current) if pulls_by_merge_sha else None
        if current in merge_shas:
            if len(parents) == 1 and pull is not None:
                number = pull.get("number")
                method = resolved_methods.get(number) if isinstance(number, int) else None
                rebased_commits.update(
                    _collect_rebased_commits(
                        repo,
                        pull,
                        current,
                        indexed,
                        merge_method=method,
                    )
                )
            current = next_sha
            continue
        related = request("GET", f"/repos/{repo}/commits/{current}/pulls", allow=(404,)) or []
        matched = [
            p
            for p in related
            if p.get("merged_at")
            and (p.get("base") or {}).get("ref") == default
            and p.get("merge_commit_sha") == current
        ]
        if matched:
            if len(parents) == 1:
                for p in matched:
                    number = p.get("number")
                    method = resolved_methods.get(number) if isinstance(number, int) else None
                    if method is None and isinstance(number, int) and not isinstance(number, bool):
                        found_method = _authenticated_pull_merge_method(repo, p, current, signers)
                        if found_method is not None:
                            resolved_methods[number] = found_method
                            method = found_method
                    rebased_commits.update(
                        _collect_rebased_commits(
                            repo,
                            p,
                            current,
                            indexed,
                            merge_method=method,
                        )
                    )
        else:
            subject = ((commit.get("commit") or {}).get("message") or "").splitlines()[0]
            note = str(acknowledged.get(current) or acknowledged.get(current[:7]) or "")
            message = f"{current[:7]} on {default} is not associated with a merged pull request: {subject}"
            if note:
                print(f"note: acknowledged direct push {current[:7]}: {note}")
            elif strict:
                findings.append(message)
            else:
                print(f"warning: {message}")
        current = next_sha
    return findings


def audit(
    repo: str,
    limit: int,
    strict_direct: bool,
    policy_ref: str | None = None,
    policy_file: str | None = None,
) -> int:
    info = request("GET", f"/repos/{repo}")
    default = info["default_branch"]
    if policy_file:
        policy = _load_policy_file(policy_file)
        verify_script(repo, default)
        trusted_policy = True
    elif policy_ref:
        policy = load_policy(repo, policy_ref)
        verify_script(repo, policy_ref)
        trusted_policy = True
    else:
        policy = load_policy(repo, default)
        verify_script(repo, default)
        trusted_policy = False

    strict = bool(strict_direct or policy.get("audit_strict_direct", True))
    signers = _valid_verdict_signers(policy)
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
        if isinstance(raw_baseline, str) and re.fullmatch(r"[0-9a-f]{40}", raw_baseline.strip().lower()):
            baseline_sha = raw_baseline.strip().lower()
        else:
            violations.append("audit_baseline_sha in policy is invalid")
    ignored = {str(number) for number in policy.get("audit_ignore_prs") or []}
    acknowledged = policy.get("audit_acknowledged_direct") or {}
    direct_limit = int(policy.get("audit_direct_commits") or 40)
    if strict and not trusted_policy:
        since = ""
        baseline_sha = ""
        ignored = set()
        acknowledged = {}
        direct_limit = max(direct_limit, 40)
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
    audited_pulls = eligible[:limit]
    checked = 0
    pull_methods: dict[int, str] = {}
    for pull in audited_pulls:
        number = pull["number"]
        checked += 1
        head = pull["head"]["sha"]
        merge_sha = pull.get("merge_commit_sha")
        comments = paginate(f"/repos/{repo}/issues/{number}/comments")
        passed = False
        for comment in comments:
            author = (comment.get("user") or {}).get("login")
            if not signers or not isinstance(author, str) or author not in signers:
                continue
            for match in re.finditer(rf"<!--\s*{VERDICT_MARKER}\s*(\{{[\s\S]*?\}})\s*-->", comment.get("body") or ""):
                try:
                    verdict = json.loads(match.group(1))
                except ValueError:
                    continue
                if (
                    verdict.get("repo") == repo
                    and verdict.get("pr") == number
                    and verdict.get("head_sha") == head
                    and verdict.get("merge_sha") == merge_sha
                    and verdict.get("verdict") == "pass"
                    and verdict.get("merged") is True
                ):
                    passed = True
                    method = verdict.get("merge_method")
                    if isinstance(method, str) and isinstance(number, int) and not isinstance(number, bool):
                        pull_methods[number] = method
        if not passed:
            violations.append(f"#{number} merged at {head[:7]} without an authenticated passing verdict")
    listing = request(
        "GET",
        f"/repos/{repo}/commits",
        params={"sha": default, "per_page": 100},
    ) or []
    default_tip = listing[0]["sha"] if listing else ""
    first_parent = _first_parent_shas(listing)
    baseline_verified = False
    default_pulls = [
        pull for pull in audited_pulls if (pull.get("base") or {}).get("ref") == default
    ]
    if not default_tip:
        if baseline_sha or default_pulls:
            violations.append(f"could not resolve {default} tip; rollback audit is incomplete")
    else:
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
