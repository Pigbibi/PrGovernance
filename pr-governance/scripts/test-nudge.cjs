'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { run, marker } = require('./nudge.cjs');
const defaults = require('../policy.default.json');

const HEAD = 'a'.repeat(40);
const codex = defaults.reviewers.find(entry => entry.provider === 'codex');
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
