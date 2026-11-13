'use strict';

// Posts one review request per head when no configured reviewer has published a
// receipt for it. Dispatch mentions follow policy.review_routing; any listed
// reviewer may still satisfy ai-review when it posts a supported marker.

const gate = require('./gate.cjs');
const defaults = require('../policy.default.json');

const MIN_HEAD_AGE_MS = 10 * 60 * 1000;
const MAX_PULL_REQUESTS = 100;

const marker = head => `<!-- governance-nudge:${head} -->`;

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

function alreadyNudged(comments, head) {
  const needle = marker(head);
  return comments.some(comment => typeof comment.body === 'string' && comment.body.includes(needle));
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

function nudgeBody(head, mentions) {
  const lines = [
    ...mentions,
    '',
    marker(head),
    '',
    'This head has no AI review receipt after 10 minutes.',
    'Dispatch order: Codex → Claude → Cursor.',
    'If both above are unavailable, a human should comment `cursor review` or `bugbot run`',
    '(Bugbot ignores those commands when posted by a bot or GitHub App).',
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
  if (alreadyNudged(comments, head)) return 'nudged';
  const age = await headAge(github, repo, head);
  if (age === null || age < MIN_HEAD_AGE_MS) return 'too-new';
  await github.rest.issues.createComment({
    ...repo,
    issue_number: pr.number,
    body: nudgeBody(head, config.mentions),
  });
  core.info(`Requested a review for #${pr.number} at ${head.slice(0, 7)}`);
  return 'requested';
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
