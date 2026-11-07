'use strict';

// pr-governance/v3 evaluator.
//
// Pure functions only: no I/O, no timers and no Node built-ins. This file is
// embedded verbatim into the generated reusable workflow, so it has to run in
// any JavaScript host with nothing but the language itself.

const SCHEMA = 'pr-governance/v3';
const MODES = ['enforce', 'local', 'report-only'];
const POLICY_FIELDS = ['version', 'mode', 'reviewer', 'r0_paths', 'r2_paths',
  'dependabot_template_exemption', 'max_evidence_age_hours'];
const POLICY_OPTIONAL_FIELDS = ['owner'];
const REVIEWER_FIELDS = ['provider', 'app_id', 'user_id', 'login'];
const OWNER_FIELDS = ['user_id', 'login'];
const PROVIDERS = ['codex'];
const MARKER_NAMES = ['codex-review-receipt:v1', 'codex-review-state:v1'];
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

function validatePolicy(policy) {
  sameKeys(policy, POLICY_FIELDS, 'policy', POLICY_OPTIONAL_FIELDS);
  assert(policy.version === SCHEMA, `Unsupported policy version: ${String(policy.version)}`);
  assert(MODES.includes(policy.mode), `Unsupported policy mode: ${String(policy.mode)}`);
  sameKeys(policy.reviewer, REVIEWER_FIELDS, 'reviewer');
  assert(PROVIDERS.includes(policy.reviewer.provider), `Unsupported reviewer provider: ${String(policy.reviewer.provider)}`);
  assert(isPositiveId(policy.reviewer.app_id), 'Invalid reviewer app id');
  assert(isPositiveId(policy.reviewer.user_id), 'Invalid reviewer user id');
  assert(typeof policy.reviewer.login === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]*\[bot\]$/.test(policy.reviewer.login),
    'Invalid reviewer login');
  // The owner comes from protected repository variables, so the committed
  // policy may leave it out. When it is present, it must be well formed.
  if (policy.owner !== undefined) {
    sameKeys(policy.owner, OWNER_FIELDS, 'owner');
    assert(isPositiveId(policy.owner.user_id), 'Invalid owner user id');
    assert(typeof policy.owner.login === 'string' && policy.owner.login.length > 0, 'Invalid owner login');
  }
  for (const field of ['r0_paths', 'r2_paths']) {
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
  return policy;
}

// --------------------------------------------------------- path classifyng ---

const PROTECTED_TOKEN = new RegExp('(^|[/_.-])(auth(?:entication|orization)?|oauth|login|session|tokens?'
  + '|credentials?|secrets?|iam|permissions?|privacy|storage|trad(?:e|es|ing)|execut(?:ion|or)s?|orders?'
  + '|brokers?|risk|deploy(?:ment)?|release|runtime|strateg(?:y|ies)|governance|settings?|config(?:uration)?)'
  + '([/_.-]|$)');
const MANIFEST = new RegExp('(^|/)(dockerfile(?:\\..*)?|docker-compose[^/]*|compose\\.ya?ml|vercel\\.json'
  + '|wrangler\\.(?:toml|jsonc?)|firebase\\.json|package(?:-lock)?\\.json|requirements[^/]*|pyproject\\.toml'
  + '|setup\\.(?:py|cfg)|uv\\.lock|poetry\\.lock|yarn\\.lock|pnpm-lock\\.yaml|makefile|.*\\.config\\.[^/]+)$');
const GOVERNANCE_SCRIPT = /^scripts\/[^/]*(?:check|verify|validate|hygiene|lint)[^/]*\.(?:py|sh|js|cjs|mjs|ts)$/;
const SECRET_MATERIAL = /\.(?:tf|tfvars|pem|key|p12|pfx)$/;

function pathTier(path, policy) {
  assert(typeof path === 'string' && path.length > 0 && !path.startsWith('/') && !path.includes('\\')
    && !path.split('/').some(part => part === '..' || part === '.' || part === ''), 'Unknown path');
  const lowered = path.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
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

function classify(files, expected, policy, options = {}) {
  assert(Array.isArray(files) && files.length > 0 && files.length === expected && files.length < 3000,
    'Incomplete file list');
  assert(new Set(files.map(file => file.filename)).size === files.length, 'Duplicate file');
  const dependabot = options.dependabot || {};
  const allowlisted = dependabot.detected && Array.isArray(dependabot.action_files) ? dependabot.action_files : [];
  let tier = 'R0';
  const rules = [];
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
    assert(lines.filter(line => line.startsWith('+')).length === file.additions
      && lines.filter(line => line.startsWith('-')).length === file.deletions, 'Incomplete patch');
    assert(patch || (file.additions === 0 && file.deletions === 0 && file.status === 'renamed'), 'Missing patch');
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
    if (fileTier > tier) tier = fileTier;
    rules.push({ paths, tier: fileTier });
  }
  return { tier, rules };
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
  review_not_required: 'Low-risk prose: reviewer evidence not required',
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
  const review = format === 'codex-review-receipt:v1' ? payload?.review : payload?.code_review;
  if (!review || typeof review !== 'object' || Array.isArray(review)) return null;
  if (typeof review.commit_sha !== 'string') return null;
  if (format === 'codex-review-receipt:v1') {
    const unresolved = review.unresolved_findings;
    let flagged = null;
    if (typeof unresolved === 'boolean') flagged = unresolved;
    else if (Number.isSafeInteger(unresolved) && unresolved >= 0) flagged = unresolved > 0;
    const coverage = typeof review.coverage === 'string' ? review.coverage.trim().toLowerCase() : '';
    return { commit_sha: review.commit_sha, status: 'completed', unresolved: flagged,
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

function reviewerEvidence(snapshot, policy, now) {
  const reviewer = policy.reviewer;
  const empty = { provider: reviewer.provider, state: 'pending', reason: 'review_pending', comment_id: null,
    format: null, commit_sha: null, coverage: null, unresolved: null };
  const candidates = (snapshot.comments || [])
    .filter(comment => matchesReviewer(comment.user, reviewer) && typeof comment.body === 'string' && carriesMarker(comment.body))
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
  Object.assign(bound, { format: found[0].name, commit_sha: evidence.commit_sha,
    coverage: evidence.coverage, unresolved: evidence.unresolved });
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

function unresolvedReviewerThreads(snapshot, policy) {
  return (snapshot.threads || [])
    .filter(thread => thread.isResolved !== true && matchesThreadAuthor(thread.author, policy.reviewer))
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
  let review = risk.tier === 'R0'
    ? { provider: policy.reviewer.provider, state: 'success', reason: 'review_not_required', comment_id: null,
      format: null, commit_sha: null, coverage: null, unresolved: null }
    : reviewerEvidence(snapshot, policy, now);
  // Thread state comes from GitHub, the marker from the provider. The stricter
  // reading wins, and a resolved-or-missing thread never proves a clean review.
  if (threads.length && review.state !== 'failure') review = { ...review, state: 'failure', reason: 'review_threads' };
  const blocking = threads.map(id => `thread:${id}`);
  if (review.reason === 'review_findings') blocking.push('marker:unresolved_findings');
  const tierOK = risk.tier !== 'R2' || labels.applied !== null;
  const allowed = review.state === 'success' && tierOK && template.ok;
  let reason;
  if (review.state === 'failure') reason = review.reason;
  else if (!tierOK) reason = 'clearing_label_required';
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
  const gateDescription = gateState === 'success'
    ? `${risk.tier}: ${cleared || (review.reason === 'review_not_required' ? 'low-risk prose' : 'review verified')}`
    : gateState === 'pending' ? `${risk.tier}: waiting for reviewer`
      : `${risk.tier}: ${GATE_TEXT[reason] || REVIEW_TEXT[reason] || reason}`;
  const evidenceSha = digest({
    binding: expected,
    tier: risk.tier,
    mode: policy.mode,
    review: { format: review.format, comment_id: review.comment_id, commit_sha: review.commit_sha,
      coverage: review.coverage, unresolved: review.unresolved, state: review.state, reason: review.reason },
    threads: (snapshot.threads || []).map(stableThread),
    labels: { applied: labels.applied, records: labels.records },
    template: { ok: template.ok, exempt: template.exempt },
    dependabot,
    commits: (snapshot.commits || []).map(commit => ({ author: commit.author?.login ?? null,
      committer: commit.committer?.login ?? null, verified: commit.commit?.verification?.verified === true })),
  });
  return {
    policy_version: SCHEMA,
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
      { context: 'ai-review', state: review.state, description: REVIEW_TEXT[review.reason] },
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
  SCHEMA, MODES, CLEARING_LABELS, MARKER_NAMES, REVIEW_TEXT,
  sha256Hex, canonical, digest, isSha,
  validatePolicy, pathTier, classify, completeTemplate, binding,
  stableComment, stableThread, matchesReviewer, matchesThreadAuthor, normalizeLogin,
  reviewerEvidence, dependabotEvidence, labelEvidence, templateVerdict, evaluate,
};
