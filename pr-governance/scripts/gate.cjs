'use strict';

// pr-governance/v3 evaluator.
//
// Pure functions only: no I/O, no timers and no Node built-ins. This file is
// embedded verbatim into the generated reusable workflow, so it has to run in
// any JavaScript host with nothing but the language itself.

const SCHEMA = 'pr-governance/v4';
const LEGACY_SCHEMA = 'pr-governance/v3';
const SCHEMAS = [LEGACY_SCHEMA, SCHEMA];
const MODES = ['enforce', 'local', 'report-only'];
const POLICY_FIELDS = ['version', 'mode', 'reviewer', 'r0_paths', 'r2_paths',
  'dependabot_template_exemption', 'max_evidence_age_hours'];
const POLICY_OPTIONAL_FIELDS = ['owner', 'reviewers', 'review_routing', 'max_r1_diff_lines',
  'r3_paths', 'review_requirements'];
const REVIEW_REQUIREMENT_FIELDS = ['r0', 'r1', 'r2', 'r3', 'distinct_providers'];
const REVIEWER_FIELDS = ['provider', 'app_id', 'user_id', 'login'];
const OWNER_FIELDS = ['user_id', 'login'];
const PROVIDERS = ['claude', 'codex', 'cursor', 'deepseek', 'opencode'];
const MARKER_NAMES = [
  'ai-review-receipt:v1',
  'codex-review-receipt:v1',
  'codex-review-state:v1',
];
const ROUTING_FIELDS = ['dispatch_mentions'];
const COMPLETE_COVERAGE = ['complete', 'completed', 'full', 'reported_complete', 'all'];
const DEPENDABOT = 'dependabot[bot]';
const CLEARING_LABELS = ['owner-approved', 'agent-approved'];

const assert = (condition, message) => { if (!condition) throw new Error(message); };

// ---------------------------------------------------------------- digests ---

function utf8Bytes(text) {
  const bytes = [];
  for (let index = 0; index < text.length; index++) {
    const point = text.codePointAt(index);
    if (point > 0xffff) index++;
    if (point < 0x80) bytes.push(point);
    else if (point < 0x800) bytes.push(0xc0 | (point >> 6), 0x80 | (point & 63));
    else if (point < 0x10000) bytes.push(0xe0 | (point >> 12), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63));
    else bytes.push(0xf0 | (point >> 18), 0x80 | ((point >> 12) & 63), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63));
  }
  return Uint8Array.from(bytes);
}

const ROUND = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const rotate = (value, bits) => (value >>> bits) | (value << (32 - bits));

function sha256Hex(text) {
  const bytes = utf8Bytes(String(text));
  const total = Math.ceil((bytes.length + 9) / 64) * 64;
  const block = new Uint8Array(total);
  block.set(bytes);
  block[bytes.length] = 0x80;
  const view = new DataView(block.buffer);
  view.setUint32(total - 8, Math.floor((bytes.length * 8) / 0x100000000));
  view.setUint32(total - 4, (bytes.length * 8) >>> 0);
  const state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const schedule = new Uint32Array(64);
  for (let offset = 0; offset < total; offset += 64) {
    for (let index = 0; index < 16; index++) schedule[index] = view.getUint32(offset + index * 4);
    for (let index = 16; index < 64; index++) {
      const a = schedule[index - 15];
      const b = schedule[index - 2];
      const s0 = rotate(a, 7) ^ rotate(a, 18) ^ (a >>> 3);
      const s1 = rotate(b, 17) ^ rotate(b, 19) ^ (b >>> 10);
      schedule[index] = (schedule[index - 16] + s0 + schedule[index - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let index = 0; index < 64; index++) {
      const s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
      const choice = (e & f) ^ (~e & g);
      const t1 = (h + s1 + choice + ROUND[index] + schedule[index]) >>> 0;
      const s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + majority) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0; state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0; state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0; state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0; state[7] = (state[7] + h) >>> 0;
  }
  return state.map(value => value.toString(16).padStart(8, '0')).join('');
}

// Sorted keys and no undefined leaves: the same evidence always hashes the same.
function canonical(value) {
  if (value === undefined) return 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const digest = value => sha256Hex(canonical(value));
const isSha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const matchesPath = (path, rule) => rule.endsWith('/') ? path.startsWith(rule) : path === rule;
const normalizeLogin = login => String(login || '').replace(/\[bot\]$/i, '').toLowerCase();

// ----------------------------------------------------------------- policy ---

function sameKeys(object, expected, label, optional = []) {
  assert(object && typeof object === 'object' && !Array.isArray(object), `Invalid ${label}`);
  const allowed = new Set([...expected, ...optional]);
  const actual = Object.keys(object);
  assert(actual.every(key => allowed.has(key))
    && expected.every(key => Object.prototype.hasOwnProperty.call(object, key)),
    `Invalid ${label} fields`);
}

const isPositiveId = value => Number.isSafeInteger(value) && value > 0;

function validateReviewer(reviewer, label) {
  sameKeys(reviewer, REVIEWER_FIELDS, label);
  assert(PROVIDERS.includes(reviewer.provider), `Unsupported reviewer provider: ${String(reviewer.provider)}`);
  assert(isPositiveId(reviewer.app_id), `Invalid ${label} app id`);
  assert(isPositiveId(reviewer.user_id), `Invalid ${label} user id`);
  assert(typeof reviewer.login === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]*\[bot\]$/.test(reviewer.login),
    `Invalid ${label} login`);
}

const sameReviewer = (left, right) => left.provider === right.provider
  && left.app_id === right.app_id
  && left.user_id === right.user_id
  && normalizeLogin(left.login) === normalizeLogin(right.login);

function reviewerChain(policy) {
  const chain = Array.isArray(policy.reviewers) && policy.reviewers.length
    ? policy.reviewers
    : [policy.reviewer];
  for (const entry of chain) validateReviewer(entry, 'reviewer');
  assert(sameReviewer(chain[0], policy.reviewer), 'reviewer must match reviewers[0]');
  const ids = new Set();
  for (const entry of chain) {
    assert(!ids.has(entry.user_id), 'Duplicate reviewer user id in reviewers');
    ids.add(entry.user_id);
  }
  return chain;
}

function validateReviewRequirements(policy) {
  const requirements = policy.review_requirements;
  sameKeys(requirements, REVIEW_REQUIREMENT_FIELDS, 'review_requirements');
  const chain = reviewerChain(policy);
  for (const tier of ['r0', 'r1', 'r2', 'r3']) {
    const count = requirements[tier];
    assert(Number.isSafeInteger(count) && count >= 1 && count <= chain.length,
      `Invalid review requirement for ${tier}`);
  }
  assert(requirements.r0 <= requirements.r1
    && requirements.r1 <= requirements.r2
    && requirements.r2 <= requirements.r3,
  'Review requirements must be monotonic');
  assert(typeof requirements.distinct_providers === 'boolean',
    'Invalid distinct_providers');
  if (requirements.distinct_providers) {
    const providers = new Set(chain.map(reviewer => reviewer.provider));
    assert(providers.size >= requirements.r3,
      'Not enough distinct reviewer providers');
  }
  return requirements;
}

function validatePolicy(policy) {
  sameKeys(policy, POLICY_FIELDS, 'policy', POLICY_OPTIONAL_FIELDS);
  assert(SCHEMAS.includes(policy.version), `Unsupported policy version: ${String(policy.version)}`);
  assert(MODES.includes(policy.mode), `Unsupported policy mode: ${String(policy.mode)}`);
  validateReviewer(policy.reviewer, 'reviewer');
  if (policy.reviewers !== undefined) reviewerChain(policy);
  if (policy.version === SCHEMA) {
    assert(Array.isArray(policy.r3_paths), 'Invalid r3_paths');
    assert(policy.review_requirements !== undefined, 'Missing review_requirements');
    validateReviewRequirements(policy);
  } else {
    assert(policy.r3_paths === undefined && policy.review_requirements === undefined,
      'v4 fields require pr-governance/v4');
  }
  // The owner comes from protected repository variables, so the committed
  // policy may leave it out. When it is present, it must be well formed.
  if (policy.owner !== undefined) {
    sameKeys(policy.owner, OWNER_FIELDS, 'owner');
    assert(isPositiveId(policy.owner.user_id), 'Invalid owner user id');
    assert(typeof policy.owner.login === 'string' && policy.owner.login.length > 0, 'Invalid owner login');
  }
  for (const field of policy.version === SCHEMA ? ['r0_paths', 'r2_paths', 'r3_paths'] : ['r0_paths', 'r2_paths']) {
    const rules = policy[field];
    assert(Array.isArray(rules), `Invalid ${field}`);
    assert(new Set(rules).size === rules.length, `Duplicate rule in ${field}`);
    for (const rule of rules) {
      assert(typeof rule === 'string' && rule.length > 0 && !rule.startsWith('/') && !rule.includes('\\')
        && !rule.replace(/\/$/, '').split('/').some(part => part === '..' || part === '.' || part === ''),
      `Invalid ${field} rule: ${String(rule)}`);
    }
  }
  assert(typeof policy.dependabot_template_exemption === 'boolean', 'Invalid dependabot_template_exemption');
  assert(typeof policy.max_evidence_age_hours === 'number' && policy.max_evidence_age_hours >= 1
    && policy.max_evidence_age_hours <= 720, 'Invalid max_evidence_age_hours');
  if (policy.max_r1_diff_lines !== undefined) {
    assert(Number.isSafeInteger(policy.max_r1_diff_lines) && policy.max_r1_diff_lines >= 50
      && policy.max_r1_diff_lines <= 5000, 'Invalid max_r1_diff_lines');
  }
  if (policy.review_routing !== undefined) {
    sameKeys(policy.review_routing, ROUTING_FIELDS, 'review_routing');
    const mentions = policy.review_routing.dispatch_mentions;
    assert(Array.isArray(mentions) && mentions.length > 0, 'Invalid dispatch_mentions');
    for (const mention of mentions) {
      assert(typeof mention === 'string' && mention.length > 0, 'Invalid dispatch mention');
    }
  }
  return policy;
}

// --------------------------------------------------------- path classifyng ---

const PROTECTED_TOKEN = new RegExp('(^|[/_.-])(auth(?:entication|orization)?|oauth|login|session|tokens?'
  + '|credentials?|secrets?|iam|permissions?|privacy|storage|trad(?:e|es|ing)|execut(?:ion|or)s?|orders?'
  + '|brokers?|risk|deploy(?:ment)?|release|runtime|strateg(?:y|ies)|governance|settings?|config(?:uration)?)'
  + '([/_.-]|$)');
const MANIFEST = new RegExp('(^|/)(dockerfile(?:\\..*)?|docker-compose[^/]*|compose\\.ya?ml|vercel\\.json'
  + '|wrangler\\.(?:toml|jsonc?)|firebase\\.json|package(?:-lock)?\\.json|requirements[^/]*|pyproject\\.toml'
  + '|setup\\.(?:py|cfg)|uv\\.lock|poetry\\.lock|yarn\\.lock|pnpm-lock\\.yaml|makefile|.*\\.config\\.[^/]+'
  + '|\\.ruff\\.toml|ruff-shared\\.toml|pyrightconfig\\.json|\\.importlinter|importlinter\\.toml'
  + '|build\\.gradle(?:\\.kts)?|settings\\.gradle(?:\\.kts)?|\\.pre-commit-config\\.yaml'
  + '|knip\\.jsonc?|\\.jscpd\\.json)$');
const LOCKFILE_OR_PROSE = /(?:^|\/)(?:package-lock\.json|uv\.lock|poetry\.lock|yarn\.lock|pnpm-lock\.yaml|cargo\.lock|gemfile\.lock)$|\.(?:md|txt|rst)$/i;
const FIXTURE_PATH = /(?:^|\/)fixtures(?:\/|$)/i;
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec)(?:\/|$)|(?:\.|_)(?:test|spec)\.[^/]+$/i;
const DEFAULT_MAX_R1_DIFF_LINES = 500;
const GOVERNANCE_SCRIPT = /^scripts\/[^/]*(?:check|verify|validate|hygiene|lint)[^/]*\.(?:py|sh|js|cjs|mjs|ts)$/;
const SECRET_MATERIAL = /\.(?:tf|tfvars|pem|key|p12|pfx)$/;
const R3_TOKEN = new RegExp('(^|[/_.-])(iam|secrets?|credentials?|production|prod'
  + '|live[-_]?trading|terraform|destroy|migrations?)([/_.-]|$)');

function pathTier(path, policy) {
  assert(typeof path === 'string' && path.length > 0 && !path.startsWith('/') && !path.includes('\\')
    && !path.split('/').some(part => part === '..' || part === '.' || part === ''), 'Unknown path');
  const lowered = path.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  // v4 isolates changes that can alter production authority, credentials or
  // destructive state. Repositories can add explicit paths without weakening
  // the canonical protected-token floor.
  if (policy.version === SCHEMA
    && (R3_TOKEN.test(lowered) || policy.r3_paths.some(rule => matchesPath(path, rule)))) return 'R3';
  // Protected paths outrank prose, examples and fixtures: a document that names
  // a credential is not low risk.
  if (lowered.startsWith('.github/')
    || /(^|\/)(agents|claude)\.md$/.test(lowered)
    || /(^|\/)(codeowners|\.coderabbit\.ya?ml|\.env(?:[._-].*)?)$/.test(lowered)
    || PROTECTED_TOKEN.test(lowered)
    || MANIFEST.test(lowered)
    || GOVERNANCE_SCRIPT.test(lowered)
    || SECRET_MATERIAL.test(lowered)
    || policy.r2_paths.some(rule => matchesPath(path, rule))) return 'R2';
  return policy.r0_paths.some(rule => matchesPath(path, rule)) && /\.(?:md|txt)$/.test(lowered) ? 'R0' : 'R1';
}

const isWorkflowPath = path => path.startsWith('.github/workflows/');

// A Dependabot repin keeps the action and changes only its ref. Swapping in a
// different action is a different change and takes the normal tier.
function pureActionRepin(file) {
  if (typeof file.patch !== 'string' || !file.patch) return false;
  const changed = file.patch.split('\n')
    .filter(line => /^[+-]/.test(line) && !/^(?:\+\+\+|---)/.test(line))
    .map(line => ({ sign: line[0], text: line.slice(1) }));
  const pinned = changed.filter(entry => /^\s*-?\s*uses\s*:/.test(entry.text));
  if (!pinned.length || pinned.length !== changed.length) return false;
  const targets = sign => pinned.filter(entry => entry.sign === sign)
    .map(entry => /^\s*-?\s*uses\s*:\s*["']?([^@"'\s]+)@/.exec(entry.text)?.[1] ?? null);
  const removed = targets('-');
  const added = targets('+');
  return removed.length > 0 && removed.length === added.length
    && removed.every((target, index) => target !== null && target === added[index]);
}

// The files endpoint may omit large text patches. Collection can recover them
// from an immutable compare diff; classification still requires exact counts.
function completePatch(file) {
  const patch = typeof file.patch === 'string' ? file.patch : '';
  const lines = patch.split('\n');
  return lines.filter(line => line.startsWith('+')).length === file.additions
    && lines.filter(line => line.startsWith('-')).length === file.deletions
    && Boolean(patch || (file.additions === 0 && file.deletions === 0 && file.status === 'renamed'));
}

function classify(files, expected, policy, options = {}) {
  assert(Array.isArray(files) && files.length > 0 && files.length === expected && files.length < 3000,
    'Incomplete file list');
  assert(new Set(files.map(file => file.filename)).size === files.length, 'Duplicate file');
  const dependabot = options.dependabot || {};
  const allowlisted = dependabot.detected && Array.isArray(dependabot.action_files) ? dependabot.action_files : [];
  let tier = 'R0';
  const rules = [];
  let effectiveDiffLines = 0;
  let newMonolith = false;
  const maxR1DiffLines = Number.isSafeInteger(policy.max_r1_diff_lines)
    ? policy.max_r1_diff_lines : DEFAULT_MAX_R1_DIFF_LINES;
  for (const file of files) {
    assert(['added', 'modified', 'removed', 'renamed', 'copied', 'changed'].includes(file.status), 'Unknown file status');
    assert(isSha(file.sha), 'Missing file object SHA');
    assert(Number.isSafeInteger(file.additions) && file.additions >= 0
      && Number.isSafeInteger(file.deletions) && file.deletions >= 0, 'Unknown diff size');
    if (file.status === 'renamed') assert(file.previous_filename, 'Missing previous path');
    const paths = [file.filename, file.previous_filename].filter(Boolean);
    let fileTier = paths.map(path => pathTier(path, policy)).sort().at(-1);
    // Count actual hunk lines: missing or truncated patches cannot attest coverage.
    const patch = file.patch || '';
    const lines = patch.split('\n');
    assert(completePatch(file), 'Incomplete patch');
    const changed = lines.filter(line => /^[+-]/.test(line)).map(line => line.slice(1));
    // R0 is deliberately narrow: even inline code, links and HTML need a reviewer.
    if (fileTier === 'R0' && (file.status !== 'modified'
      || changed.some(line => /[`~<>\[\]{}\\$]|^\s{4}|(?:https?:|javascript:|\b(?:curl|wget|npm|python|sudo|bash)\b)/i.test(line)))) fileTier = 'R1';
    if (paths.some(path => /\.(?:md|txt)$/.test(path))
      && changed.some(line => /\b(?:auth|iam|secret|credential|permission|trading|orders?|strategy|deploy|workflow|owner-approved)\b|认证|授权|凭据|交易|下单|部署/i.test(line))) fileTier = 'R2';
    // A verified Dependabot update inside an allowlisted workflow is nothing but
    // a repin, so it may merge without a clearing label. Everything else in a
    // workflow definition still needs one.
    if (fileTier === 'R2' && dependabot.detected && allowlisted.includes(file.filename)
      && isWorkflowPath(file.filename) && !file.previous_filename && pureActionRepin(file)) fileTier = 'R1';
    if (!LOCKFILE_OR_PROSE.test(file.filename) && !FIXTURE_PATH.test(file.filename)) {
      effectiveDiffLines += file.additions + file.deletions;
      if (file.status === 'added' && !TEST_PATH.test(file.filename) && file.additions > maxR1DiffLines) {
        newMonolith = true;
      }
    }
    if (fileTier > tier) tier = fileTier;
    rules.push({ paths, tier: fileTier });
  }
  let volumeEscalated = false;
  if ((effectiveDiffLines > maxR1DiffLines || newMonolith) && tier < 'R2' && !dependabot.detected) {
    tier = 'R2';
    volumeEscalated = true;
  }
  return { tier, rules, effectiveDiffLines, newMonolith, volumeEscalated };
}

// --------------------------------------------------------------- evidence ---

function binding(snapshot, policySha) {
  const pr = snapshot.pr;
  assert(isSha(pr.head.sha) && isSha(pr.base.sha), 'Unknown commit');
  assert(isSha(snapshot.policyCommit), 'Unknown policy commit');
  return {
    repository: snapshot.repository,
    repository_id: pr.base?.repo?.id ?? null,
    pr_number: pr.number,
    head_sha: pr.head.sha,
    base_sha: pr.base.sha,
    policy_commit: snapshot.policyCommit,
    policy_sha256: policySha,
    diff_sha256: digest(snapshot.files.map(file => ({
      filename: file.filename,
      previous_filename: file.previous_filename || null,
      status: file.status,
      sha: file.sha,
      additions: file.additions,
      deletions: file.deletions,
      patch: file.patch || '',
    })).sort((left, right) => (left.filename < right.filename ? -1 : left.filename > right.filename ? 1 : 0))),
  };
}

// Bodies never enter a digest or a log line: only identity and timing do.
const stableComment = comment => ({
  id: comment.id,
  user: { id: comment.user?.id ?? null, login: comment.user?.login ?? null, type: comment.user?.type ?? null },
  created_at: comment.created_at ?? null,
  updated_at: comment.updated_at ?? null,
});

const stableThread = thread => ({
  id: thread.id,
  isResolved: thread.isResolved === true,
  isOutdated: thread.isOutdated === true,
  author: thread.author?.login ?? null,
});

const sameLogin = (user, reviewer) => Boolean(user) && normalizeLogin(user.login) === normalizeLogin(reviewer.login);

function matchesReviewer(user, reviewer) {
  return sameLogin(user, reviewer) && user.id === reviewer.user_id;
}

// GraphQL returns the thread author login for every thread but the numeric id
// only when the viewer may read it, so a present id has to match and an absent
// one falls back to the normalised login.
function matchesThreadAuthor(author, reviewer) {
  if (!sameLogin(author, reviewer)) return false;
  if (author.id === undefined || author.id === null) return true;
  return author.id === reviewer.user_id;
}

// Collects every marker occurrence, terminated by `-->`. A marker whose body
// contains the terminator therefore fails to parse instead of being accepted.
function markerPayloads(body, name) {
  const needle = new RegExp(`<!--\\s*${name.replace(/[.:]/g, '\\$&')}\\s*`, 'g');
  const payloads = [];
  let match;
  while ((match = needle.exec(body)) !== null) {
    const start = match.index + match[0].length;
    const end = body.indexOf('-->', start);
    payloads.push(end < 0 ? null : body.slice(start, end).trim());
  }
  return payloads;
}

const carriesMarker = body => MARKER_NAMES.some(name => markerPayloads(body, name).length > 0);

const REVIEW_TEXT = {
  review_complete: 'Reviewer evidence covers this head',
  review_pending: 'Waiting for reviewer evidence on this head',
  review_running: 'Reviewer review is still running on this head',
  review_malformed: 'Newest reviewer marker is malformed or ambiguous',
  review_stale: 'Reviewer evidence covers another commit',
  review_findings: 'Reviewer reported unresolved findings',
  review_findings_unknown: 'Reviewer findings state is not reported',
  review_partial: 'Reviewer coverage is incomplete',
  review_expired: 'Reviewer evidence exceeds the policy age limit',
  review_threads: 'Unresolved reviewer threads remain on this head',
};

function normalizeMarker(format, payload) {
  const receipt = format === 'ai-review-receipt:v1' || format === 'codex-review-receipt:v1';
  const review = receipt ? payload?.review : payload?.code_review;
  if (!review || typeof review !== 'object' || Array.isArray(review)) return null;
  if (typeof review.commit_sha !== 'string') return null;
  if (receipt) {
    const unresolved = review.unresolved_findings;
    let flagged = null;
    if (typeof unresolved === 'boolean') flagged = unresolved;
    else if (Number.isSafeInteger(unresolved) && unresolved >= 0) flagged = unresolved > 0;
    const coverage = typeof review.coverage === 'string' ? review.coverage.trim().toLowerCase() : '';
    // Legacy codex-review-receipt:v1 often omits status and means completed; an
    // explicit non-completed status must stay pending/running instead of passing.
    const status = typeof review.status === 'string' && review.status
      ? review.status
      : 'completed';
    return { commit_sha: review.commit_sha, status, unresolved: flagged,
      coverage: COMPLETE_COVERAGE.includes(coverage) ? 'complete' : 'partial', coverage_raw: coverage || null };
  }
  const unresolved = review.has_unresolved_findings;
  return {
    commit_sha: review.commit_sha,
    status: typeof review.status === 'string' ? review.status : '',
    unresolved: typeof unresolved === 'boolean' ? unresolved : null,
    coverage: 'complete',
    coverage_raw: null,
  };
}

function matchesAnyReviewer(user, chain) {
  return chain.some(reviewer => matchesReviewer(user, reviewer));
}

function reviewerEvidence(snapshot, policy, now) {
  const chain = reviewerChain(policy);
  const primary = chain[0];
  const empty = { provider: primary.provider, state: 'pending', reason: 'review_pending', comment_id: null,
    format: null, commit_sha: null, coverage: null, unresolved: null };
  const candidates = (snapshot.comments || [])
    .filter(comment => matchesAnyReviewer(comment.user, chain) && typeof comment.body === 'string'
      && carriesMarker(comment.body))
    .map(comment => {
      assert(Number.isSafeInteger(comment.id) && comment.id > 0, 'Unknown comment metadata');
      return { comment, stamp: Date.parse(comment.updated_at) };
    })
    .sort((left, right) => (right.stamp || 0) - (left.stamp || 0) || right.comment.id - left.comment.id);
  if (!candidates.length) return empty;
  // The newest marker-bearing comment wins before its contents are judged: a
  // newer malformed or blocking marker must not fall back to an older clean one.
  const { comment, stamp } = candidates[0];
  const bound = { ...empty, comment_id: comment.id };
  const found = [];
  for (const name of MARKER_NAMES) {
    for (const payload of markerPayloads(comment.body, name)) found.push({ name, payload });
  }
  if (found.length !== 1) return { ...bound, state: 'failure', reason: 'review_malformed' };
  let parsed;
  try {
    parsed = JSON.parse(found[0].payload);
  } catch {
    return { ...bound, state: 'failure', reason: 'review_malformed' };
  }
  const evidence = normalizeMarker(found[0].name, parsed);
  if (!evidence) return { ...bound, state: 'failure', reason: 'review_malformed' };
  const matched = chain.find(reviewer => matchesReviewer(comment.user, reviewer));
  Object.assign(bound, { provider: matched?.provider ?? primary.provider, format: found[0].name,
    commit_sha: evidence.commit_sha, coverage: evidence.coverage, unresolved: evidence.unresolved });
  if (evidence.status !== 'completed') return { ...bound, state: 'pending', reason: 'review_running' };
  if (evidence.commit_sha !== snapshot.pr.head.sha) return { ...bound, state: 'failure', reason: 'review_stale' };
  if (evidence.unresolved === true) return { ...bound, state: 'failure', reason: 'review_findings' };
  if (evidence.unresolved === null) return { ...bound, state: 'failure', reason: 'review_findings_unknown' };
  if (evidence.coverage !== 'complete') return { ...bound, state: 'failure', reason: 'review_partial' };
  const limit = policy.max_evidence_age_hours * 3600;
  if (!Number.isFinite(stamp)) return { ...bound, state: 'failure', reason: 'review_malformed' };
  if (now - Math.floor(stamp / 1000) > limit) return { ...bound, state: 'failure', reason: 'review_expired' };
  return { ...bound, state: 'success', reason: 'review_complete' };
}

function multiReviewerEvidence(snapshot, policy, now, tier) {
  const chain = reviewerChain(policy);
  const required = policy.review_requirements[tier.toLowerCase()];
  const results = chain.map(reviewer => reviewerEvidence(snapshot, {
    ...policy,
    reviewer,
    reviewers: [reviewer],
  }, now));
  const summaries = results.map(result => ({
    provider: result.provider,
    state: result.state,
    reason: result.reason,
    comment_id: result.comment_id,
    commit_sha: result.commit_sha,
    coverage: result.coverage,
    unresolved: result.unresolved,
  }));
  const blocking = results.find(result => result.state === 'failure'
    && result.reason !== 'review_stale');
  const successful = results.filter(result => result.state === 'success');
  const providers = [...new Set(successful.map(result => result.provider))].sort();
  const enough = successful.length >= required
    && (!policy.review_requirements.distinct_providers || providers.length >= required);
  const common = {
    required,
    count: successful.length,
    providers,
    receipts: summaries,
  };
  if (blocking) return { ...blocking, ...common };
  if (enough) return { ...successful[0], ...common };
  const running = results.find(result => result.reason === 'review_running');
  const primary = running || results[0];
  return { ...primary, ...common, state: 'pending',
    reason: running ? 'review_running' : 'review_pending' };
}

function unresolvedReviewerThreads(snapshot, policy) {
  const chain = reviewerChain(policy);
  return (snapshot.threads || [])
    .filter(thread => thread.isResolved !== true && chain.some(reviewer => matchesThreadAuthor(thread.author, reviewer)))
    .map(thread => thread.id)
    .sort();
}

function dependabotEvidence(snapshot, policy) {
  const result = { detected: false, action_files: [], template_exempt: true === policy.dependabot_template_exemption };
  if (snapshot.pr.user?.login !== DEPENDABOT) return result;
  const commits = snapshot.commits || [];
  // The commits API truncates at 250 entries; an incomplete history cannot prove
  // who wrote every commit in the head.
  if (!commits.length || commits.length >= 250) return { ...result, template_exempt: false };
  const verified = commits.every(commit => commit.author?.login === DEPENDABOT
    && commit.committer?.login === 'web-flow'
    && commit.commit?.verification?.verified === true);
  if (!verified) return { ...result, template_exempt: false };
  const policyFile = snapshot.dependabotPolicy;
  const actionFiles = Array.isArray(policyFile?.action_files)
    ? policyFile.action_files.filter(path => typeof path === 'string').sort()
    : [];
  return { detected: true, action_files: actionFiles, template_exempt: result.template_exempt };
}

function labelEvidence(snapshot, policy) {
  const events = (snapshot.timeline || []).filter(event => event.event === 'labeled' || event.event === 'unlabeled');
  const present = new Set((snapshot.pr.labels || []).map(label => label.name));
  const records = {};
  for (const name of CLEARING_LABELS) {
    const latest = events.filter(event => event.label?.name === name)
      .sort((left, right) => right.id - left.id)[0];
    if (!latest || latest.event !== 'labeled') continue;
    if (!present.has(name)) continue;
    // The owner label claims a human confirmation; only the configured owner id
    // can carry that claim. Any actor may claim agent-approved, and the actor is
    // recorded in the digest because the label API already requires write access.
    if (name === 'owner-approved' && latest.actor?.id !== policy.owner?.user_id) continue;
    if (!Number.isSafeInteger(latest.id) || latest.id < 1 || !Number.isSafeInteger(latest.actor?.id)) continue;
    const expected = `${name} for PR ${snapshot.pr.number} at event ${latest.id} on this head`;
    const bound = (snapshot.statuses || []).some(status => status.context === 'clearing-label'
      && status.state === 'success' && status.description === expected);
    if (!bound) continue;
    records[name] = { event_id: latest.id, actor_id: latest.actor.id, actor_login: latest.actor.login ?? null };
  }
  // A human confirmation outranks an agent's when both are bound to this head.
  const applied = records['owner-approved'] ? 'owner' : records['agent-approved'] ? 'agent' : null;
  return { applied, records, present: [...present].filter(name => CLEARING_LABELS.includes(name)).sort() };
}

function templateVerdict(snapshot, policy, dependabot) {
  if (dependabot?.detected && policy.dependabot_template_exemption === true) {
    return { ok: true, exempt: true, state: 'success', description: 'Automated dependency update: template not required' };
  }
  const ok = completeTemplate(snapshot.pr.body);
  return { ok, exempt: false, state: ok ? 'success' : 'failure',
    description: ok ? 'PR template sections complete' : 'Fill in AI, changes and verification sections' };
}

const GATE_TEXT = {
  clearing_label_required: 'needs owner-approved or agent-approved',
  owner_approval_required: 'needs owner-approved',
  pr_template_incomplete: 'PR template incomplete',
  ai_review_pending: 'waiting for reviewer',
};

function evaluate(snapshot, policy, policySha, now = Math.floor(Date.now() / 1000)) {
  validatePolicy(policy);
  assert(typeof policySha === 'string' && /^[a-f0-9]{64}$/.test(policySha), 'Unknown policy digest');
  assert(snapshot && snapshot.complete === true, 'Incomplete snapshot');
  const pr = snapshot.pr;
  assert(pr && pr.state === 'open', 'Only open pull requests are evaluated');
  assert(Number.isSafeInteger(pr.number) && pr.number > 0, 'Unknown pull request number');
  assert(Array.isArray(snapshot.commits) && snapshot.commits.length === pr.commits
    && snapshot.commits.length > 0 && snapshot.commits.length < 250, 'Incomplete commit list');
  for (const field of ['comments', 'threads', 'timeline', 'statuses']) {
    assert(Array.isArray(snapshot[field]), `Incomplete ${field}`);
  }
  const dependabot = dependabotEvidence(snapshot, policy);
  const risk = classify(snapshot.files, pr.changed_files, policy, { dependabot });
  const expected = binding(snapshot, policySha);
  const template = templateVerdict(snapshot, policy, dependabot);
  const labels = labelEvidence(snapshot, policy);
  const threads = unresolvedReviewerThreads(snapshot, policy);
  // Reviewer evidence is required at every tier: a prose-only change can still
  // introduce a misleading claim, so R0 only lowers the label requirement.
  let review = policy.version === SCHEMA
    ? multiReviewerEvidence(snapshot, policy, now, risk.tier)
    : reviewerEvidence(snapshot, policy, now);
  // Thread state comes from GitHub, the marker from the provider. The stricter
  // reading wins, and a resolved-or-missing thread never proves a clean review.
  if (threads.length && review.state !== 'failure') review = { ...review, state: 'failure', reason: 'review_threads' };
  const blocking = threads.map(id => `thread:${id}`);
  if (review.reason === 'review_findings') blocking.push('marker:unresolved_findings');
  const tierOK = risk.tier === 'R3' ? labels.applied === 'owner'
    : risk.tier !== 'R2' || labels.applied !== null;
  const allowed = review.state === 'success' && tierOK && template.ok;
  let reason;
  if (review.state === 'failure') reason = review.reason;
  else if (!tierOK) reason = risk.tier === 'R3' ? 'owner_approval_required' : 'clearing_label_required';
  else if (!template.ok) reason = 'pr_template_incomplete';
  else if (review.state === 'pending') reason = 'ai_review_pending';
  else reason = review.reason;
  const gateState = !tierOK ? 'failure'
    : review.state === 'pending' ? 'pending'
      : allowed ? 'success' : 'failure';
  // Two labels, two claims: the gate names which one cleared the high-risk path
  // so an agent-cleared merge is visible instead of passing as a human review.
  const cleared = labels.applied === 'owner' ? 'cleared by owner-approved'
    : labels.applied === 'agent' ? 'cleared by agent-approved, NOT confirmed by the owner' : null;
  const gateReasonText = reason === 'clearing_label_required' && risk.volumeEscalated
    ? 'diff volume exceeded; needs owner-approved or agent-approved'
    : (GATE_TEXT[reason] || REVIEW_TEXT[reason] || reason);
  const gateDescription = gateState === 'success'
    ? `${risk.tier}: ${cleared || 'review verified'}`
    : gateState === 'pending' ? `${risk.tier}: waiting for reviewer`
      : `${risk.tier}: ${gateReasonText}`;
  const evidenceSha = digest({
    binding: expected,
    tier: risk.tier,
    mode: policy.mode,
    review: { format: review.format, comment_id: review.comment_id, commit_sha: review.commit_sha,
      coverage: review.coverage, unresolved: review.unresolved, state: review.state, reason: review.reason,
      required: review.required ?? 1, count: review.count ?? (review.state === 'success' ? 1 : 0),
      providers: review.providers ?? [review.provider], receipts: review.receipts ?? null },
    threads: (snapshot.threads || []).map(stableThread),
    labels: { applied: labels.applied, records: labels.records },
    template: { ok: template.ok, exempt: template.exempt },
    dependabot,
    commits: (snapshot.commits || []).map(commit => ({ author: commit.author?.login ?? null,
      committer: commit.committer?.login ?? null, verified: commit.commit?.verification?.verified === true })),
  });
  return {
    policy_version: policy.version,
    mode: policy.mode,
    tier: risk.tier,
    rules: risk.rules,
    binding: expected,
    review: { ...review, description: REVIEW_TEXT[review.reason] },
    template,
    labels,
    dependabot,
    blocking_findings: blocking,
    allowed,
    reason,
    evidence_sha256: evidenceSha,
    statuses: [
      { context: 'pr-template', state: template.state, description: template.description },
      { context: 'ai-review', state: review.state,
        description: review.required > 1
          ? `${review.count}/${review.required} independent reviews verified`
          : REVIEW_TEXT[review.reason] },
      { context: 'risk-gate', state: gateState, description: gateDescription },
    ],
  };
}

// ---------------------------------------------------------------- template ---

function completeTemplate(body) {
  // Whitespace prevents joining delimiters; an unterminated comment hides the rest.
  const text = (body || '').replace(/<!--[\s\S]*?(?:-->|$)/g, ' ');
  const sections = [...text.matchAll(/^#{1,6}\s+(.+)\r?\n([\s\S]*?)(?=^#{1,6}\s|$(?![\s\S]))/gm)];
  const used = new Set();
  const present = pattern => {
    const index = sections.findIndex(([, heading, content], position) => !used.has(position) && pattern.test(heading)
      && content.replace(/```[\s\S]*?```/g, '').replace(/[-*]\s*\[[ x]\]/g, '').trim().length > 3
      && !/^\s*(?:TODO|TBD|N\/A|placeholder|\.\.\.|…|Describe the change.*|Which AI tool.*|List the checks.*)\s*$/i.test(content));
    if (index < 0) return false;
    used.add(index);
    return true;
  };
  return present(/\bAI\b|模型|人工智能/i)
    && present(/what changed|summary|problem|changes|变更|改动|做了什么/i)
    && present(/how verified|verif|validat|test(?:ing| plan)?|验证|测试/i);
}

module.exports = {
  SCHEMA, LEGACY_SCHEMA, SCHEMAS, MODES, CLEARING_LABELS, MARKER_NAMES, REVIEW_TEXT,
  sha256Hex, canonical, digest, isSha,
  validatePolicy, validateReviewRequirements, reviewerChain, validateReviewer, pathTier, completePatch, classify, completeTemplate, binding,
  stableComment, stableThread, matchesReviewer, matchesAnyReviewer, matchesThreadAuthor, normalizeLogin, markerPayloads,
  reviewerEvidence, multiReviewerEvidence, dependabotEvidence, labelEvidence, templateVerdict, evaluate,
};

