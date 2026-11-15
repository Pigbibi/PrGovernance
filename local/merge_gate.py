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
# A Codex summary body carries several marker comments; keep the capture
# greedy inside this one but never let it cross the comment terminator.
RECEIPT_MARKERS = (
    re.compile(r"<!--\s*ai-review-receipt:v1\s*(\{(?:(?!-->)[\s\S])*\})\s*-->"),
    re.compile(r"<!--\s*codex-review-receipt:v1\s*(\{(?:(?!-->)[\s\S])*\})\s*-->"),
    re.compile(r"<!--\s*codex-review-state:v1\s*(\{(?:(?!-->)[\s\S])*\})\s*-->"),
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

PLAIN_DOC = (
    re.compile(r"^(docs?)/"),
    re.compile(r"/(docs?)/"),
    re.compile(r"\.md$"),
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


def dependabot_head(repo: str, number: int) -> bool:
    commits = paginate(f"/repos/{repo}/pulls/{number}/commits")
    if not commits or len(commits) >= 250:
        return False
    return all(
        (commit.get("author") or {}).get("login") == "dependabot[bot]"
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


def _judge_provider_receipt(
    login_provider: str, marker_index: int, raw: str, head: str
) -> tuple[str, str, bool | None, bool]:
    if marker_index < 0:
        return (
            "failure",
            f"Ambiguous or disallowed AI review receipt markers in {login_provider} comment",
            True,
            False,
        )
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
    status = review.get("status") or ("completed" if marker_index != 2 else None)
    if status != "completed":
        return "pending", f"AI review {status or 'not finished'}", on_head, True
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
    repo: str, number: int, head: str, allowed_providers: set[str] | None = None
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
        matches = [
            (idx, match.group(1))
            for idx, pattern in enumerate(RECEIPT_MARKERS)
            for match in pattern.finditer(body)
        ]
        if not matches:
            continue
        updated_at = comment.get("updated_at") or ""
        comment_id = comment.get("id")
        cid = comment_id if isinstance(comment_id, int) and not isinstance(comment_id, bool) else 0
        parsed_ts = _parse_iso_timestamp(updated_at) or _EPOCH_MIN
        if len(matches) > 1 or matches[0][0] not in allowed_indices:
            marker_index, payload_raw = -1, ""
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


def codex_verdict(repo: str, number: int, head: str) -> tuple[str, str]:
    return ai_review_verdict(repo, number, head, allowed_providers={"codex"})


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


def policy_agent_logins(policy: dict[str, Any] | None) -> set[str]:
    if not isinstance(policy, dict):
        return set()
    configured = policy.get("agent_logins")
    if not isinstance(configured, list):
        configured = policy.get("approved_agent_logins")
    if not isinstance(configured, list):
        return set()
    return {login.strip() for login in configured if isinstance(login, str) and login.strip()}


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
    timeline = paginate(f"/repos/{repo}/issues/{number}/timeline")
    latest = {}
    for event in timeline:
        kind = event.get("event")
        if kind in ("committed", "head_ref_force_pushed", "head_ref_restored", "reopened"):
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
        if statuses is None:
            statuses = paginate(f"/repos/{repo}/commits/{head}/statuses")
        event_id = event.get("id")
        if event_id is not None and not isinstance(event_id, bool):
            expected = f"{name} for PR {number} at event {event_id} on this head"
            if any(
                s.get("context") == "clearing-label"
                and s.get("state") == "success"
                and (s.get("creator") or {}).get("login") == ACTIONS_BOT
                and s.get("description") == expected
                for s in statuses
            ):
                return name
        event_ts = _parse_iso_timestamp(event.get("created_at"))
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


def head_contains_base(repo: str, base: str, head: str) -> tuple[bool, str]:
    branch = request("GET", f"/repos/{repo}/branches/{urllib.parse.quote(base, safe='')}")
    base_head = branch["commit"]["sha"]
    comparison = request("GET", f"/repos/{repo}/compare/{base_head}...{head}")
    return (comparison.get("merge_base_commit") or {}).get("sha") == base_head, base_head


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
    files = paginate(f"/repos/{repo}/pulls/{number}/files")
    reasons: list[str] = []
    if len(files) != pull.get("changed_files") or len(files) >= 3000:
        reasons.append("Changed-file list is incomplete; refuse to judge a partial diff")
    contains_base, base_head = head_contains_base(repo, base_ref, head)
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
        (pull.get("user") or {}).get("login") == "dependabot[bot]" and dependabot_head(repo, number)
    )
    extra = tuple(policy.get("extra_protected_paths") or ())
    tier, fast_path = classify(files, verified_dependabot, base_action_files(repo, policy_ref), extra)
    if symlinks or not tree_ok:
        tier = "T2"
        fast_path = False
    providers = policy_review_providers(policy)
    if providers and tier != "T0" and not fast_path:
        if providers == {"codex"}:
            codex_state, codex_note = codex_verdict(repo, number, head)
        else:
            codex_state, codex_note = ai_review_verdict(
                repo, number, head, allowed_providers=providers
            )
    else:
        codex_state, codex_note = "skipped", "Not required for this change"
    if codex_state not in ("success", "skipped"):
        reasons.append(codex_note)
    agent_logins = policy_agent_logins(policy)
    label = (
        live_label(repo, number, policy.get("owner_login", ""), pull=pull, agent_logins=agent_logins)
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


def revalidate(repo: str, verdict: dict[str, Any], policy_file: str | None = None) -> None:
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
    if verdict.get("tier") == "T2":
        live = live_label(
            repo,
            verdict["pr"],
            policy.get("owner_login", ""),
            pull=pull,
            agent_logins=policy_agent_logins(policy),
        )
        if live != verdict.get("label"):
            raise Refusal("Clearing label changed since the verdict; re-run the gate")
    if verdict.get("codex") not in (None, "skipped"):
        providers = policy_review_providers(policy)
        if not providers:
            raise Refusal("AI review policy changed since the verdict; re-run the gate")
        expected_providers = verdict.get("review_providers")
        if expected_providers is not None and sorted(providers) != sorted(expected_providers):
            raise Refusal("AI review providers changed since the verdict; re-run the gate")
        if providers == {"codex"}:
            state, note = codex_verdict(repo, verdict["pr"], verdict["head_sha"])
        else:
            state, note = ai_review_verdict(
                repo, verdict["pr"], verdict["head_sha"], allowed_providers=providers
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
        revalidate(repo, verdict, policy_file=policy_file)
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


def scan_direct_pushes(repo: str, default: str, since: str, merge_shas: set, acknowledged: dict,
                       strict: bool, limit: int) -> list[str]:
    # Only main's first-parent chain is evidence of a push that bypassed the entry;
    # scanning the raw commit listing both misses chain commits behind a long branch
    # merge and reports side-branch commits that never reached main on their own.
    # Committer dates are not monotonic along ancestry, so the walk is bounded by
    # depth alone and the audit window filters each commit on its own. The listing
    # is reverse-chronological over side branches too, so ancestors missing from it
    # are fetched one by one rather than silently ending the walk.
    indexed: dict[str, dict[str, Any]] = {}
    listing = request("GET", f"/repos/{repo}/commits",
                      params={"sha": default, "per_page": 100}) or []
    for commit in listing:
        indexed.setdefault(commit["sha"], commit)
    findings: list[str] = []
    current, visited = (listing[0]["sha"] if listing else ""), 0
    while current and visited < limit:
        commit = _resolve_commit(repo, current, indexed)
        if commit is None:
            findings.append(f"{current[:7]} on {default} could not be resolved; "
                            f"the direct-push audit is incomplete")
            break
        parents = [parent.get("sha") for parent in (commit.get("parents") or [])]
        next_sha = parents[0] if parents else ""
        visited += 1
        date = ((commit.get("commit") or {}).get("committer") or {}).get("date") or ""
        if current in merge_shas or (since and date and date < since):
            current = next_sha
            continue
        related = request("GET", f"/repos/{repo}/commits/{current}/pulls", allow=(404,)) or []
        if not any(
            pull.get("merged_at") and (pull.get("base") or {}).get("ref") == default
            for pull in related
        ):
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

    owner = policy.get("owner_login", "")
    violations: list[str] = []
    raw_since = policy.get("audit_since") or ""
    since = ""
    if raw_since:
        parsed_since = _parse_iso_timestamp(raw_since)
        if parsed_since is None or parsed_since > dt.datetime.now(dt.timezone.utc):
            violations.append("audit_since in policy is invalid or in the future")
        else:
            since = parsed_since.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ignored = {str(number) for number in policy.get("audit_ignore_prs") or []}
    acknowledged = policy.get("audit_acknowledged_direct") or {}
    direct_limit = int(policy.get("audit_direct_commits") or 40)
    if strict_direct and not trusted_policy:
        since = ""
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
    checked = 0
    for pull in eligible[:limit]:
        number = pull["number"]
        checked += 1
        head = pull["head"]["sha"]
        merge_sha = pull.get("merge_commit_sha")
        comments = paginate(f"/repos/{repo}/issues/{number}/comments")
        passed = False
        for comment in comments:
            if not owner or (comment.get("user") or {}).get("login") != owner:
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
        if not passed:
            violations.append(f"#{number} merged at {head[:7]} without an authenticated passing verdict")
    merge_shas = {
        pull.get("merge_commit_sha")
        for pull in eligible[:limit]
        if pull.get("merge_commit_sha") and (pull.get("base") or {}).get("ref") == default
    }
    strict = bool(strict_direct or policy.get("audit_strict_direct", True))
    violations.extend(scan_direct_pushes(repo, default, since, merge_shas, acknowledged,
                                        strict, direct_limit))
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
