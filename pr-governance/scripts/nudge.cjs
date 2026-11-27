'use strict';

// Posts one review request per head for subscription reviewers that are turned
// on. Codex defaults on and Claude defaults off; set CODEX_REVIEW_ENABLED and
// CLAUDE_REVIEW_ENABLED to true or false. A reviewer that is off is not
// mentioned. When none remain, this script posts nothing and the DeepSeek
// reviewer takes the head. Cursor and Bugbot are not requested.

const gate = require('./gate.cjs');
const defaults = require('../policy.default.json');
const { flagsFromEnv, selectReviewRoute } = require('./review_route.cjs');

const MIN_HEAD_AGE_MS = 10 * 60 * 1000;
const MAX_PULL_REQUESTS = 100;
const QUOTA_PATTERN = /\b(?:usage\s+limit|rate\s*limit|quota\s+(?:exceeded|reached|exhausted)|out\s+of\s+credits?|limit\s+reached|try\s+again\s+later)\b|额度已用完|达到上限/i;

const marker = (head, stage = 1) => {
  if (stage === 'deepseek') return `<!-- governance-nudge:${head}:deepseek -->`;
  return stage === 1
    ? `<!-- governance-nudge:${head} -->`
    : `<!-- governance-nudge:${head}:stage${stage} -->`;
};

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
  const needle = stage === 'deepseek'
    ? `<!-- governance-nudge:${head}:deepseek -->`
    : marker(head, stage);
  return comments.find(c => typeof c.body === 'string' && c.body.includes(needle)) || null;
}

function alreadyNudged(comments, head) {
  return Boolean(findNudgeComment(comments, head, 1));
}

function reviewerQuotaHit(comments, reviewer, sinceMs) {
  if (!reviewer || sinceMs === Number.POSITIVE_INFINITY) return false;
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
  const lines = [
    ...mentions,
    '',
    marker(head, stage),
    '',
    stage === 'deepseek'
      ? 'No enabled subscription reviewer remains for this head.'
      : stage === 1
        ? 'This head has no AI review receipt after 10 minutes.'
        : 'An enabled reviewer reported a quota limit. Requesting the other enabled subscription reviewer.',
    `Enabled now: ${mentions.join(', ')}.`,
    'A subscription flag set to false is not requested. When none remain, DeepSeek reviews this head.',
    'Acceptable markers: `ai-review-receipt:v1`, `codex-review-state:v1`, `codex-review-receipt:v1`.',
  ];
  return lines.join('\n');
}

function mentionFor(provider, configured) {
  if (provider === 'codex') return configured[0] || '@codex review';
  if (provider === 'claude') return configured[1] || '@claude review';
  return null;
}

function apiReviewMention() {
  const text = String(process.env.GOVERNANCE_API_REVIEW_MENTION || '').trim();
  return text;
}

function routeFor(comments, chain, head) {
  const flags = flagsFromEnv(process.env);
  const currentRequest = findNudgeComment(comments, head, 1);
  const sinceMs = currentRequest ? Date.parse(currentRequest.created_at || '') : Number.POSITIVE_INFINITY;
  const quotaProviders = [];
  for (const reviewer of chain) {
    if (reviewerQuotaHit(comments, reviewer, sinceMs)) quotaProviders.push(reviewer.provider);
  }
  const route = selectReviewRoute({ ...flags, quotaProviders });
  const acceptable = new Set(route.kind === 'deepseek'
    ? ['deepseek', 'opencode']
    : route.providers);
  return { route, chain: chain.filter(reviewer => acceptable.has(reviewer.provider)) };
}

async function reviewRequested(github, repo, pr, core, config) {
  const head = pr.head?.sha;
  if (!head || pr.draft || pr.state !== 'open') return 'skipped';
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...repo, issue_number: pr.number, per_page: 100,
  });
  const selected = routeFor(comments, config.chain, head);
  if (receiptFor(comments, head, selected.chain)) return 'reviewed';
  if (selected.route.kind === 'deepseek') {
    if (findNudgeComment(comments, head, 'deepseek')) return 'api-fallback';
    const mention = apiReviewMention();
    if (!mention) {
      throw new Error(
        'GOVERNANCE_API_REVIEW_MENTION is required when no subscription reviewer is enabled'
      );
    }
    try {
      await github.rest.issues.createComment({
        ...repo,
        issue_number: pr.number,
        body: nudgeBody(head, [mention], 'deepseek'),
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
    core.info(`Requested DeepSeek review for #${pr.number} at ${head.slice(0, 7)}`);
    return 'api-fallback';
  }
  const s1 = findNudgeComment(comments, head, 1);
  let nextStage = 1;
  let mentions = selected.route.providers.map(provider => mentionFor(provider, config.mentions)).filter(Boolean);
  if (s1) {
    if (!s1.body.includes('@')) return 'nudged';
    const missing = mentions.filter(mention => !s1.body.includes(mention));
    if (!missing.length || findNudgeComment(comments, head, 2)) return 'nudged';
    nextStage = 2;
    mentions = missing;
  } else {
    const age = await headAge(github, repo, head);
    if (age === null || age < MIN_HEAD_AGE_MS) return 'too-new';
  }
  try {
    await github.rest.issues.createComment({
      ...repo,
      issue_number: pr.number,
      body: nudgeBody(head, mentions, nextStage),
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
