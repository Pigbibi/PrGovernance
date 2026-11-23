'use strict';

// Posts one review request per head when no configured reviewer has published a
// receipt for it. Dispatch mentions follow policy.review_routing; any listed
// reviewer may still satisfy ai-review when it posts a supported marker.

const gate = require('./gate.cjs');
const defaults = require('../policy.default.json');

const MIN_HEAD_AGE_MS = 10 * 60 * 1000;
const FALLBACK_WAIT_MS = 15 * 60 * 1000;
const MAX_PULL_REQUESTS = 100;
const QUOTA_PATTERN = /\b(?:usage\s+limit|rate\s*limit|quota\s+(?:exceeded|reached|exhausted)|out\s+of\s+credits?|limit\s+reached|try\s+again\s+later)\b|额度已用完|达到上限/i;

const marker = (head, stage = 1) => (stage === 1
  ? `<!-- governance-nudge:${head} -->`
  : `<!-- governance-nudge:${head}:stage${stage} -->`);

function dispatchMentions(policy) {
  const raw = process.env.GOVERNANCE_DISPATCH_MENTIONS_JSON;
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('GOVERNANCE_DISPATCH_MENTIONS_JSON is not valid JSON');
    }
    if (!Array.isArray(parsed) || !parsed.length || parsed.some(item => typeof item !== 'string' || !item)) {
      throw new Error('GOVERNANCE_DISPATCH_MENTIONS_JSON must be a non-empty string array');
    }
    return parsed;
  }
  return policy.review_routing?.dispatch_mentions
    ?? defaults.review_routing?.dispatch_mentions
    ?? ['@codex review', '@claude review'];
}

function reviewerConfig() {
  const raw = process.env.GOVERNANCE_REVIEWERS_JSON;
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('GOVERNANCE_REVIEWERS_JSON is not valid JSON');
    }
    if (!Array.isArray(parsed) || !parsed.length) throw new Error('GOVERNANCE_REVIEWERS_JSON must be a non-empty array');
    const policy = { ...defaults, reviewers: parsed, reviewer: parsed[0] };
    gate.validatePolicy(policy);
    return { chain: gate.reviewerChain(policy), mentions: dispatchMentions(policy) };
  }
  const policy = gate.validatePolicy(defaults);
  return { chain: gate.reviewerChain(policy), mentions: dispatchMentions(policy) };
}

function receiptFor(comments, head, chain) {
  return comments.some(comment => gate.matchesAnyReviewer(comment.user, chain)
    && typeof comment.body === 'string'
    && gate.MARKER_NAMES.some(name => comment.body.includes(name))
    && comment.body.includes(head));
}

function findNudgeComment(comments, head, stage) {
  if (stage === 1) {
    const legacy = `<!-- governance-nudge:${head} -->`;
    const explicit = `<!-- governance-nudge:${head}:stage1 -->`;
    return comments.find(c => typeof c.body === 'string' && (c.body.includes(legacy) || c.body.includes(explicit))) || null;
  }
  const needle = marker(head, stage);
  return comments.find(c => typeof c.body === 'string' && c.body.includes(needle)) || null;
}

function alreadyNudged(comments, head) {
  return Boolean(findNudgeComment(comments, head, 1));
}

function reviewerQuotaHit(comments, reviewer, sinceMs) {
  if (!reviewer) return false;
  return comments.some(c => {
    if (!gate.matchesReviewer(c.user, reviewer) || typeof c.body !== 'string') return false;
    if (gate.MARKER_NAMES.some(name => c.body.includes(name))) return false;
    const ts = Date.parse(c.created_at || '');
    if (Number.isFinite(sinceMs) && Number.isFinite(ts) && ts < sinceMs) return false;
    return QUOTA_PATTERN.test(c.body);
  });
}

async function headAge(github, repo, head) {
  try {
    const { data } = await github.rest.repos.getCommit({ ...repo, ref: head });
    const date = Date.parse(data.commit?.committer?.date || data.commit?.author?.date || '');
    return Number.isFinite(date) ? Date.now() - date : null;
  } catch {
    return null;
  }
}

function nudgeBody(head, mentions, stage = 1) {
  const mentionList = stage === 1
    ? [mentions[0] || '@codex review']
    : stage === 2
      ? [mentions[1] || '@claude review']
      : [];
  const stageNote = stage === 1
    ? 'This head has no AI review receipt after 10 minutes (primary: Codex).'
    : stage === 2
      ? 'Primary reviewer did not produce a receipt (quota/timeout). Falling back to secondary reviewer.'
      : 'Primary and secondary reviewers did not produce a receipt. A human must comment `cursor review` or `bugbot run` (Bugbot ignores bot-posted triggers).';
  const lines = [
    ...mentionList,
    ...(mentionList.length ? [''] : []),
    marker(head, stage),
    '',
    stageNote,
    'Dispatch order: Codex → Claude → Cursor.',
    'Acceptable markers: `ai-review-receipt:v1`, `codex-review-state:v1`, `codex-review-receipt:v1`.',
  ];
  return lines.join('\n');
}

async function reviewRequested(github, repo, pr, core, config) {
  const head = pr.head?.sha;
  if (!head || pr.draft || pr.state !== 'open') return 'skipped';
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...repo, issue_number: pr.number, per_page: 100,
  });
  if (receiptFor(comments, head, config.chain)) return 'reviewed';
  const s1 = findNudgeComment(comments, head, 1);
  const s2 = findNudgeComment(comments, head, 2);
  const s3 = findNudgeComment(comments, head, 3);
  const now = Date.now();
  let nextStage = null;
  if (!s1) {
    const age = await headAge(github, repo, head);
    if (age === null || age < MIN_HEAD_AGE_MS) return 'too-new';
    nextStage = 1;
  } else if (!s2 && config.mentions.length > 1) {
    const s1Ms = Date.parse(s1.created_at || '');
    const primaryQuota = reviewerQuotaHit(comments, config.chain[0], s1Ms);
    const timedOut = Number.isFinite(s1Ms) && (now - s1Ms) >= FALLBACK_WAIT_MS;
    if (!primaryQuota && !timedOut) return 'nudged';
    nextStage = 2;
  } else if (!s3 && config.chain.some(r => r.provider === 'cursor')) {
    const prev = s2 || s1;
    const prevMs = Date.parse(prev.created_at || '');
    const secondaryQuota = s2 ? reviewerQuotaHit(comments, config.chain[1], prevMs) : false;
    const timedOut = Number.isFinite(prevMs) && (now - prevMs) >= FALLBACK_WAIT_MS;
    if (!secondaryQuota && !timedOut) return 'nudged';
    nextStage = 3;
  } else {
    return 'nudged';
  }
  try {
    await github.rest.issues.createComment({
      ...repo,
      issue_number: pr.number,
      body: nudgeBody(head, config.mentions, nextStage),
    });
  } catch (err) {
    if (err && err.status === 403) {
      throw new Error(
        'Cannot create the review-request comment: the Review request workflow needs '
        + 'pull-requests: write (and issues: write). GitHub returned 403 '
        + 'Resource not accessible by integration.'
      );
    }
    throw err;
  }
  core.info(`Requested stage-${nextStage} review for #${pr.number} at ${head.slice(0, 7)}`);
  return nextStage === 1 ? 'requested' : `fallback-stage${nextStage}`;
}

async function run({ github, context, core }) {
  const config = reviewerConfig();
  const repo = { owner: context.repo.owner, repo: context.repo.repo };
  let pulls;
  if (context.payload.pull_request) {
    pulls = [context.payload.pull_request];
  } else {
    pulls = await github.paginate(github.rest.pulls.list, {
      ...repo, state: 'open', per_page: 100, sort: 'updated', direction: 'desc',
    });
    if (pulls.length > MAX_PULL_REQUESTS) {
      core.info(`Evaluating the ${MAX_PULL_REQUESTS} most recently updated of ${pulls.length} open pull requests`);
      pulls = pulls.slice(0, MAX_PULL_REQUESTS);
    }
  }

  const counts = {};
  for (const pr of pulls) {
    const outcome = await reviewRequested(github, repo, pr, core, config);
    counts[outcome] = (counts[outcome] || 0) + 1;
  }
  core.info(`Review requests: ${Object.entries(counts).map(([key, value]) => `${key}=${value}`).join(' ') || 'none'}`);
}

module.exports = { run, receiptFor, alreadyNudged, marker, reviewerConfig, nudgeBody, dispatchMentions };
