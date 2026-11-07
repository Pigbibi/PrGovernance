'use strict';

// Posts one review request per head when the reviewer has published no receipt
// for it. The marker is keyed to the head, so a later push gets its own request
// without repeating this one, and a receipt already present is never overridden.

const CODEX_LOGIN = /^chatgpt-codex-connector(?:\[bot\])?$/;
const RECEIPT_MARKERS = ['codex-review-state:v1', 'codex-review-receipt:v1'];
const MIN_HEAD_AGE_MS = 10 * 60 * 1000;
const MAX_PULL_REQUESTS = 100;

const marker = head => `<!-- governance-nudge:${head} -->`;

function receiptFor(comments, head) {
  return comments.some(comment => CODEX_LOGIN.test(comment.user?.login || '')
    && typeof comment.body === 'string'
    && RECEIPT_MARKERS.some(name => comment.body.includes(name))
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

async function reviewRequested(github, repo, pr, core) {
  const head = pr.head?.sha;
  if (!head || pr.draft || pr.state !== 'open') return 'skipped';
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...repo, issue_number: pr.number, per_page: 100,
  });
  if (receiptFor(comments, head)) return 'reviewed';
  if (alreadyNudged(comments, head)) return 'nudged';
  const age = await headAge(github, repo, head);
  if (age === null || age < MIN_HEAD_AGE_MS) return 'too-new';
  await github.rest.issues.createComment({
    ...repo,
    issue_number: pr.number,
    body: `@codex review\n\n${marker(head)}\n\nThis head has no review receipt after 10 minutes.`,
  });
  core.info(`Requested a review for #${pr.number} at ${head.slice(0, 7)}`);
  return 'requested';
}

async function run({ github, context, core }) {
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
    const outcome = await reviewRequested(github, repo, pr, core);
    counts[outcome] = (counts[outcome] || 0) + 1;
  }
  core.info(`Review requests: ${Object.entries(counts).map(([key, value]) => `${key}=${value}`).join(' ') || 'none'}`);
}

module.exports = { run, receiptFor, alreadyNudged, marker };
