'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { run, marker } = require('./nudge.cjs');
const defaults = require('../policy.default.json');

const HEAD = 'a'.repeat(40);
const codex = defaults.reviewer;
const OLD = new Date(Date.now() - 60 * 60 * 1000).toISOString();
const core = { info() {} };

function harness({ comments = [], headDate = OLD, draft = false, state = 'open' } = {}) {
  const posted = [];
  const github = {
    paginate: async (fn, params) => (fn === github.rest.pulls.list ? [{
      number: 7, draft, state, head: { sha: HEAD, ref: 'feat' },
    }] : comments),
    rest: {
      pulls: { list: Symbol('list') },
      issues: {
        listComments: Symbol('listComments'),
        createComment: async ({ body }) => posted.push(body),
      },
      repos: {
        getCommit: async () => ({ data: { commit: { committer: { date: headDate } } } }),
      },
    },
  };
  const context = { repo: { owner: 'o', repo: 'r' }, payload: {} };
  return { github, context, posted };
}

test('requests a review for an old head with no receipt', async () => {
  const h = harness();
  await run({ ...h, core });
  assert.equal(h.posted.length, 1);
  assert.match(h.posted[0], /@codex review/);
  assert.match(h.posted[0], /governance-nudge:a{40}/);
});

test('does not repeat the request for the same head', async () => {
  const h = harness({ comments: [{ user: { login: 'someone' }, body: marker(HEAD) }] });
  await run({ ...h, core });
  assert.equal(h.posted.length, 0);
});

test('does not request a review twice when a receipt exists', async () => {
  const h = harness({
    comments: [{
      user: { id: codex.user_id, login: codex.login },
      body: `<!-- codex-review-state:v1 {"code_review":{"status":"completed","commit_sha":"${HEAD}"}} -->`,
    }],
  });
  await run({ ...h, core });
  assert.equal(h.posted.length, 0);
});

test('accepts the legacy receipt marker', async () => {
  const h = harness({
    comments: [{
      user: { id: codex.user_id, login: 'chatgpt-codex-connector' },
      body: `<!-- codex-review-receipt:v1 {"review":{"commit_sha":"${HEAD}","coverage":"complete","unresolved_findings":false}} -->`,
    }],
  });
  await run({ ...h, core });
  assert.equal(h.posted.length, 0);
});

test('waits for a fresh head', async () => {
  const h = harness({ headDate: new Date().toISOString() });
  await run({ ...h, core });
  assert.equal(h.posted.length, 0);
});

test('skips drafts and closed pull requests', async () => {
  for (const options of [{ draft: true }, { state: 'closed' }]) {
    const h = harness(options);
    await run({ ...h, core });
    assert.equal(h.posted.length, 0);
  }
});

test('reports a clear error when commenting is forbidden', async () => {
  const h = harness();
  h.github.rest.issues.createComment = async () => {
    const err = new Error('Resource not accessible by integration');
    err.status = 403;
    throw err;
  };
  await assert.rejects(
    () => run({ ...h, core }),
    /pull-requests: write/
  );
  assert.equal(h.posted.length, 0);
});

test('falls back to @claude review immediately when codex hits quota after stage 1', async () => {
  const s1Time = new Date(Date.now() - 2 * 60 * 1000).toISOString();
  const quotaTime = new Date(Date.now() - 1 * 60 * 1000).toISOString();
  const h = harness({
    comments: [
      { user: { login: 'github-actions[bot]' }, created_at: s1Time, body: marker(HEAD, 1) },
      { user: { id: codex.user_id, login: codex.login }, created_at: quotaTime, body: 'Codex usage limit reached. Please try again later.' },
    ],
  });
  await run({ ...h, core });
  assert.equal(h.posted.length, 1);
  assert.match(h.posted[0], /@claude review/);
  assert.doesNotMatch(h.posted[0], /@codex review/);
  assert.match(h.posted[0], /governance-nudge:a{40}:stage2/);
});

test('falls back to @claude review on timeout and escalates to cursor human prompt at stage 3', async () => {
  const oldS1 = new Date(Date.now() - 20 * 60 * 1000).toISOString();
  const h2 = harness({
    comments: [{ user: { login: 'github-actions[bot]' }, created_at: oldS1, body: marker(HEAD, 1) }],
  });
  await run({ ...h2, core });
  assert.equal(h2.posted.length, 1);
  assert.match(h2.posted[0], /@claude review/);

  const prevReviewers = process.env.GOVERNANCE_REVIEWERS_JSON;
  process.env.GOVERNANCE_REVIEWERS_JSON = JSON.stringify([
    codex,
    { provider: 'claude', app_id: 1236702, user_id: 209825114, login: 'claude[bot]' },
    { provider: 'cursor', app_id: 1210556, user_id: 206951365, login: 'cursor[bot]' },
  ]);
  try {
    const h3 = harness({
      comments: [
        { user: { login: 'github-actions[bot]' }, created_at: oldS1, body: marker(HEAD, 1) },
        { user: { login: 'github-actions[bot]' }, created_at: oldS1, body: marker(HEAD, 2) },
      ],
    });
    await run({ ...h3, core });
    assert.equal(h3.posted.length, 1);
    assert.match(h3.posted[0], /cursor review/);
    assert.match(h3.posted[0], /governance-nudge:a{40}:stage3/);
  } finally {
    if (prevReviewers === undefined) delete process.env.GOVERNANCE_REVIEWERS_JSON;
    else process.env.GOVERNANCE_REVIEWERS_JSON = prevReviewers;
  }
});
