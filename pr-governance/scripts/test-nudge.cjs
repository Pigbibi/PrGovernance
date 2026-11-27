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
  assert.doesNotMatch(h.posted[0], /@claude review/);
  assert.doesNotMatch(h.posted[0], /cursor review/);
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

test('a Codex quota after this head request asks DeepSeek when Claude is off', async () => {
  const previous = process.env.GOVERNANCE_API_REVIEW_MENTION;
  process.env.GOVERNANCE_API_REVIEW_MENTION = '@example-ai-reviewer review';
  const s1Time = new Date(Date.now() - 2 * 60 * 1000).toISOString();
  const quotaTime = new Date(Date.now() - 1 * 60 * 1000).toISOString();
  try {
    const h = harness({
      comments: [
        { user: { login: 'github-actions[bot]' }, created_at: s1Time, body: `${marker(HEAD, 1)}\n@codex review` },
        { user: { id: codex.user_id, login: codex.login }, created_at: quotaTime, body: 'Codex usage limit reached. Please try again later.' },
      ],
    });
    await run({ ...h, core });
    assert.equal(h.posted.length, 1);
    assert.match(h.posted[0], /@example-ai-reviewer review/);
    assert.match(h.posted[0], /governance-nudge:a{40}:deepseek/);
    assert.doesNotMatch(h.posted[0], /@claude review/);
  } finally {
    if (previous === undefined) delete process.env.GOVERNANCE_API_REVIEW_MENTION;
    else process.env.GOVERNANCE_API_REVIEW_MENTION = previous;
  }
});

test('an older Codex quota comment does not skip the current head', async () => {
  const h = harness({
    comments: [{
      user: { id: codex.user_id, login: codex.login },
      created_at: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      body: 'Codex usage limit reached. Please try again later.',
    }],
  });
  await run({ ...h, core });
  assert.equal(h.posted.length, 1);
  assert.match(h.posted[0], /@codex review/);
  assert.doesNotMatch(h.posted[0], /:deepseek/);
});

test('mentions Claude after a Codex quota only when Claude is enabled', async () => {
  const previous = process.env.CLAUDE_REVIEW_ENABLED;
  process.env.CLAUDE_REVIEW_ENABLED = 'true';
  const s1Time = new Date(Date.now() - 2 * 60 * 1000).toISOString();
  const quotaTime = new Date(Date.now() - 1 * 60 * 1000).toISOString();
  try {
    const h = harness({
      comments: [
        { user: { login: 'github-actions[bot]' }, created_at: s1Time, body: `${marker(HEAD, 1)}\n@codex review` },
        { user: { id: codex.user_id, login: codex.login }, created_at: quotaTime, body: 'Codex usage limit reached. Please try again later.' },
      ],
    });
    await run({ ...h, core });
    assert.equal(h.posted.length, 1);
    assert.match(h.posted[0], /@claude review/);
    assert.doesNotMatch(h.posted[0], /@codex review/);
    assert.doesNotMatch(h.posted[0], /cursor review/);
    assert.match(h.posted[0], /governance-nudge:a{40}:stage2/);
  } finally {
    if (previous === undefined) delete process.env.CLAUDE_REVIEW_ENABLED;
    else process.env.CLAUDE_REVIEW_ENABLED = previous;
  }
});

test('both subscriptions off posts the configured DeepSeek mention once', async () => {
  const previousCodex = process.env.CODEX_REVIEW_ENABLED;
  const previousClaude = process.env.CLAUDE_REVIEW_ENABLED;
  const previousMention = process.env.GOVERNANCE_API_REVIEW_MENTION;
  process.env.CODEX_REVIEW_ENABLED = 'false';
  process.env.CLAUDE_REVIEW_ENABLED = 'false';
  process.env.GOVERNANCE_API_REVIEW_MENTION = '@example-ai-reviewer review the security checklist';
  try {
    const comments = [];
    const h = harness({ comments });
    await run({ ...h, core });
    assert.equal(h.posted.length, 1);
    assert.match(h.posted[0], /@example-ai-reviewer review the security checklist/);
    assert.doesNotMatch(h.posted[0], /cursor review/);
    comments.push({ user: { login: 'github-actions[bot]' }, body: h.posted[0] });
    h.posted.length = 0;
    await run({ ...h, core });
    assert.equal(h.posted.length, 0);
  } finally {
    if (previousCodex === undefined) delete process.env.CODEX_REVIEW_ENABLED;
    else process.env.CODEX_REVIEW_ENABLED = previousCodex;
    if (previousClaude === undefined) delete process.env.CLAUDE_REVIEW_ENABLED;
    else process.env.CLAUDE_REVIEW_ENABLED = previousClaude;
    if (previousMention === undefined) delete process.env.GOVERNANCE_API_REVIEW_MENTION;
    else process.env.GOVERNANCE_API_REVIEW_MENTION = previousMention;
  }
});

test('a custom Codex dispatch mention is posted unchanged', async () => {
  const previous = process.env.GOVERNANCE_DISPATCH_MENTIONS_JSON;
  process.env.GOVERNANCE_DISPATCH_MENTIONS_JSON = JSON.stringify([
    '@codex review with the repository-specific security checklist',
    '@claude review',
  ]);
  try {
    const h = harness();
    await run({ ...h, core });
    assert.match(h.posted[0], /@codex review with the repository-specific security checklist/);
  } finally {
    if (previous === undefined) delete process.env.GOVERNANCE_DISPATCH_MENTIONS_JSON;
    else process.env.GOVERNANCE_DISPATCH_MENTIONS_JSON = previous;
  }
});
