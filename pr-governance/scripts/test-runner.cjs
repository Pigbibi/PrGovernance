'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const gate = require('./gate.cjs');
const runner = require('./runner.cjs');
const { fixture, receiptMarker, labelEvent, clearRecord, HEAD, BASE, POLICY_SHA, NOW } = require('./fixtures.cjs');

const POLICY = fixture().policy;

function mock(f, options = {}) {
  const statuses = [];
  const failures = [];
  const warnings = [];
  const infos = [];
  const calls = [];
  const summary = [];
  const state = {
    pull: structuredClone(f.snapshot.pr),
    files: f.snapshot.files,
    commits: f.snapshot.commits,
    comments: f.snapshot.comments,
    timeline: f.snapshot.timeline,
    statuses: f.snapshot.statuses,
    threads: f.snapshot.threads,
    open: options.open || [{ number: f.snapshot.pr.number, head: { sha: f.snapshot.pr.head.sha } }],
    branch: options.branch || BASE,
    dependabotPolicy: options.dependabotPolicy ?? f.snapshot.dependabotPolicy,
  };
  const rest = {
    pulls: {
      get: async () => ({ data: structuredClone(state.pull) }),
      list: async () => state.open,
      listFiles: async () => state.files,
      listCommits: async () => state.commits,
    },
    issues: {
      listComments: async () => state.comments,
      listEvents: async () => state.timeline,
    },
    repos: {
      listCommitStatusesForRef: async () => state.statuses,
      getBranch: async () => ({ data: { commit: { sha: state.branch } } }),
      getContent: async ({ path, ref }) => {
        calls.push({ method: 'getContent', params: { path, ref } });
        if (path !== runner.DEPENDABOT_POLICY_PATH) {
          return Promise.reject(Object.assign(new Error('Not Found'), { status: 404 }));
        }
        if (!state.dependabotPolicy) {
          return Promise.reject(Object.assign(new Error('Not Found'), { status: 404 }));
        }
        return { data: { type: 'file', encoding: 'base64',
          content: Buffer.from(JSON.stringify(state.dependabotPolicy)).toString('base64') } };
      },
      createCommitStatus: async input => {
        const data = { ...input, creator: { id: 41898282, login: 'github-actions[bot]' } };
        statuses.push(data);
        state.statuses.unshift(data);
        return { data };
      },
    },
  };
  const names = new Map([[rest.pulls.list, 'pulls'], [rest.pulls.listFiles, 'files'],
    [rest.pulls.listCommits, 'commits'], [rest.issues.listComments, 'comments'],
    [rest.issues.listEvents, 'events'], [rest.repos.listCommitStatusesForRef, 'statuses']]);
  const github = {
    rest,
    paginate: async (method, params) => {
      const name = names.get(method) || 'unknown';
      calls.push({ method: name, params });
      if (name === 'pulls') return structuredClone(state.open);
      if (name === 'files') return structuredClone(state.files);
      if (name === 'commits') return structuredClone(state.commits);
      if (name === 'comments') return structuredClone(state.comments);
      if (name === 'events') return structuredClone(state.timeline);
      if (name === 'statuses') return structuredClone(state.statuses);
      throw new Error(`Unexpected paginate: ${name}`);
    },
    graphql: async () => ({
      repository: { pullRequest: { reviewThreads: {
        nodes: structuredClone(state.threads), pageInfo: { hasNextPage: false, endCursor: null },
      } } },
    }),
  };
  const core = {
    setFailed: message => failures.push(message),
    warning: message => warnings.push(message),
    info: message => infos.push(message),
    summary: {
      addHeading: text => { summary.push(text); return core.summary; },
      addCodeBlock: text => { summary.push(text); return core.summary; },
      addRaw: text => { summary.push(text); return core.summary; },
      write: async () => {},
    },
  };
  const context = {
    repo: { owner: 'example-org', repo: 'example-repo' },
    eventName: options.eventName || 'pull_request_target',
    payload: options.payload || { action: 'opened', pull_request: { number: f.snapshot.pr.number } },
    ref: options.ref || `refs/heads/${options.branch || 'main'}`,
    serverUrl: 'https://github.example',
    runId: 123,
  };
  return { github, context, core, statuses, failures, warnings, infos, calls, summary, state };
}

const runMock = (m, overrides = {}) => runner.run({ github: m.github, context: m.context, core: m.core,
  policy: POLICY, policySha: POLICY_SHA, policyCommit: BASE, defaultBranch: 'main', now: NOW, ...overrides });

const states = m => m.statuses.map(status => [status.context, status.state]);

// ------------------------------------------------------------- targeting ---

test('a single pull request event evaluates only that pull request', async () => {
  const m = mock(fixture());
  assert.deepEqual(await runner.selectTargets(m.github, m.context, 'main'), [42]);
  assert.deepEqual(m.calls, []);
});

test('push and schedule sweep every open pull request', async () => {
  for (const eventName of ['push', 'schedule']) {
    const m = mock(fixture(), { eventName, open: [{ number: 4 }, { number: 5 }] });
    m.context.payload = {};
    assert.deepEqual(await runner.selectTargets(m.github, m.context, 'main'), [4, 5]);
  }
});

test('a large sweep is never truncated', async () => {
  const open = Array.from({ length: 40 }, (_, index) => ({ number: index + 1 }));
  const m = mock(fixture(), { eventName: 'schedule', open });
  m.context.payload = {};
  assert.equal((await runner.selectTargets(m.github, m.context, 'main')).length, 40);
});

test('a closed pull request re-evaluates the remaining open ones', async () => {
  const m = mock(fixture(), { open: [{ number: 42 }, { number: 43 }] });
  m.context.payload = { action: 'closed', pull_request: { number: 42 } };
  assert.deepEqual(await runner.selectTargets(m.github, m.context, 'main'), [43]);
});

test('a comment on an issue that is not a pull request evaluates nothing', async () => {
  const m = mock(fixture(), { eventName: 'issue_comment' });
  m.context.payload = { issue: { number: 8 } };
  assert.deepEqual(await runner.selectTargets(m.github, m.context, 'main'), []);
  m.context.payload = { issue: { number: 8, pull_request: {} } };
  assert.deepEqual(await runner.selectTargets(m.github, m.context, 'main'), [8]);
});

test('dispatch validates the number and the default branch', async () => {
  const m = mock(fixture(), { eventName: 'workflow_dispatch' });
  m.context.payload = { inputs: { pr_number: '42' } };
  assert.deepEqual(await runner.selectTargets(m.github, m.context, 'main'), [42]);
  m.context.payload.inputs.pr_number = '1; rm -rf /';
  await assert.rejects(runner.selectTargets(m.github, m.context, 'main'));
  m.context.payload.inputs.pr_number = '42';
  m.context.ref = 'refs/heads/feature';
  await assert.rejects(runner.selectTargets(m.github, m.context, 'main'), /default branch/);
});

test('an unsupported event fails instead of guessing a target', async () => {
  const m = mock(fixture(), { eventName: 'watch' });
  m.context.payload = {};
  await assert.rejects(runner.selectTargets(m.github, m.context, 'main'), /Unsupported event/);
});

test('review threads paginate to the last page and refuse a repeating cursor', async () => {
  const m = mock(fixture());
  let page = 0;
  m.github.graphql = async (query, params) => {
    page++;
    assert.equal(params.cursor, page === 1 ? null : 'cursor1');
    return { repository: { pullRequest: { reviewThreads: {
      nodes: [{ id: `thread-${page}`, isResolved: page === 1, comments: { nodes: [{ author: { login: 'agent' } }] } }],
      pageInfo: { hasNextPage: page === 1, endCursor: page === 1 ? 'cursor1' : null },
    } } } };
  };
  const threads = await runner.readThreads(m.github, m.context.repo, 42);
  assert.equal(threads.length, 2);
  assert.equal(threads[1].author.login, 'agent');
  m.github.graphql = async () => ({ repository: { pullRequest: { reviewThreads: {
    nodes: [], pageInfo: { hasNextPage: true, endCursor: null },
  } } } });
  await assert.rejects(runner.readThreads(m.github, m.context.repo, 42), /page/);
});

test('every collection endpoint is paginated with the maximum page size', async () => {
  const m = mock(fixture());
  await runner.collect(m.github, m.context, 42, BASE);
  assert.deepEqual([...new Set(m.calls.filter(call => call.method !== 'getContent').map(call => call.method))].sort(),
    ['comments', 'commits', 'events', 'files', 'statuses']);
  assert.ok(m.calls.every(call => call.method === 'getContent' || call.params.per_page === 100));
});

test('the dependency policy is read from the trusted base only', async () => {
  const m = mock(fixture(), { dependabotPolicy: { action_files: ['.github/workflows/ci.yml'] } });
  const snapshot = await runner.collect(m.github, m.context, 42, BASE);
  assert.deepEqual(snapshot.dependabotPolicy, { action_files: ['.github/workflows/ci.yml'] });
  const reads = m.calls.filter(call => call.method === 'getContent');
  assert.deepEqual(reads.map(call => call.params), [{ path: runner.DEPENDABOT_POLICY_PATH, ref: BASE }]);
});

// -------------------------------------------------------------- verdicts ---

test('a reviewed pull request publishes three success statuses and fails nothing', async () => {
  const f = receiptMarker(fixture());
  const m = mock(f);
  await runMock(m);
  assert.deepEqual(states(m), [['pr-template', 'success'], ['ai-review', 'success'], ['risk-gate', 'success']]);
  assert.ok(m.statuses.every(status => status.sha === HEAD));
  assert.equal(m.failures.length, 0);
  assert.match(m.summary.join('\n'), /"reason": "review_complete"/);
});

test('an incomplete template fails the run once, after publishing', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.pr.body = 'Nothing useful.';
  const m = mock(f);
  await runMock(m);
  assert.deepEqual(states(m), [['pr-template', 'failure'], ['ai-review', 'success'], ['risk-gate', 'failure']]);
  assert.equal(m.failures.length, 1);
  assert.match(m.failures[0], /#42/);
});

test('an unchanged sweep appends no statuses and reports nothing', async () => {
  const f = receiptMarker(fixture());
  const first = mock(f);
  await runMock(first);
  assert.equal(first.statuses.length, 3);
  for (let index = 0; index < 3; index++) {
    const next = mock(f);
    next.context.runId += index + 1;
    await runMock(next);
    assert.equal(next.statuses.length, 0);
    assert.equal(next.failures.length, 0);
  }
});

test('a matching status from another publisher is replaced, not trusted', async () => {
  const f = receiptMarker(fixture());
  await runMock(mock(f));
  for (const status of f.snapshot.statuses) status.creator = { id: 1, login: 'author' };
  const m = mock(f);
  await runMock(m);
  assert.equal(m.statuses.length, 3);
});

test('a closed pull request publishes nothing', async () => {
  const f = fixture();
  f.snapshot.pr.state = 'closed';
  const m = mock(f);
  await runMock(m);
  assert.equal(m.statuses.length, 0);
  assert.equal(m.failures.length, 0);
});

test('a non default base branch is refused', async () => {
  const f = fixture();
  f.snapshot.pr.base.ref = 'release';
  const m = mock(f);
  await runMock(m);
  assert.ok(m.statuses.some(status => status.state === 'error'));
  assert.equal(m.failures.length, 1);
});

// ---------------------------------------------------------- base outdated ---

test('a stale base publishes a base-outdated verdict without failing the sweep', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.pr.base.sha = 'e'.repeat(40);
  const m = mock(f);
  await runMock(m);
  assert.deepEqual(states(m), [['pr-template', 'success'], ['ai-review', 'failure'], ['risk-gate', 'failure']]);
  const verdict = m.statuses.find(status => status.context === 'risk-gate');
  assert.equal(verdict.description, 'R1: base-outdated');
  assert.equal(m.failures.length, 0);
  assert.equal(m.warnings.length, 1);
  assert.match(m.warnings[0], /rebase/);
  const summary = JSON.parse(m.summary.find(entry => entry.trim().startsWith('{')));
  assert.equal(summary.reason, 'base-outdated');
  assert.equal(summary.base_sha, 'e'.repeat(40));
  assert.equal(summary.policy_commit, BASE);
  assert.equal(summary.tier, 'R1');
  assert.equal(summary.allowed, false);
});

test('a stale base still reports an incomplete template', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.pr.base.sha = 'e'.repeat(40);
  f.snapshot.pr.body = 'Nothing useful.';
  const m = mock(f);
  await runMock(m);
  assert.deepEqual(states(m), [['pr-template', 'failure'], ['ai-review', 'failure'], ['risk-gate', 'failure']]);
  assert.equal(m.failures.length, 0);
});

test('one stale pull request does not stop the sweep from evaluating the rest', async () => {
  const f = receiptMarker(fixture());
  const other = '9'.repeat(40);
  const m = mock(f, { eventName: 'push', open: [{ number: 42, head: { sha: HEAD } }, { number: 43, head: { sha: other } }] });
  m.context.payload = {};
  const pull = structuredClone(m.state.pull);
  m.github.rest.pulls.get = async input => ({
    data: input.pull_number === 42
      ? { ...structuredClone(pull), base: { ...pull.base, sha: 'e'.repeat(40) } }
      : { ...structuredClone(pull), head: { sha: other } },
  });
  const result = await runMock(m);
  // The stale pull request is a stable verdict, not a failure; the sweep still
  // evaluated the second one and failed only for it.
  assert.equal(m.failures.length, 1);
  assert.match(m.failures[0], /#43/);
  assert.doesNotMatch(m.failures[0], /#42/);
  assert.ok(m.statuses.some(status => status.description === 'R1: base-outdated'));
  assert.deepEqual([...new Set(m.statuses.map(status => status.sha))].sort(), [other, HEAD].sort());
  assert.deepEqual(result.failures.map(item => item.number), [43]);
});

// ------------------------------------------------------------ shared head ---

test('a shared head publishes error statuses and never a pass', async () => {
  const f = receiptMarker(fixture());
  const m = mock(f, { open: [{ number: 42, head: { sha: HEAD } }, { number: 99, head: { sha: HEAD } }] });
  const result = await runMock(m);
  assert.deepEqual(states(m), [['pr-template', 'error'], ['ai-review', 'error'], ['risk-gate', 'error']]);
  assert.ok(m.statuses.every(status => /shares this head/.test(status.description)));
  assert.equal(m.failures.length, 1);
  assert.deepEqual(result.failures.map(item => item.message), ['SHARED_HEAD']);
});

test('a sibling that appears during evaluation still blocks the pass', async () => {
  const f = receiptMarker(fixture());
  const m = mock(f);
  let lists = 0;
  const list = m.github.paginate;
  m.github.paginate = async (method, params) => {
    if (method === m.github.rest.pulls.list) {
      lists++;
      if (lists === 2) {
        m.state.open = [{ number: 42, head: { sha: HEAD } }, { number: 77, head: { sha: HEAD } }];
      }
    }
    return list(method, params);
  };
  await runMock(m);
  assert.ok(m.statuses.some(status => status.state === 'error'));
  assert.ok(m.statuses.every(status => status.state !== 'success'));
});

// ------------------------------------------------------------ status limit ---

test('a context with 998 statuses still publishes a real verdict', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.statuses = Array.from({ length: 998 }, () => ({ context: 'risk-gate', state: 'success',
    description: 'Old success', creator: { id: 41898282, login: 'github-actions[bot]' } }));
  const m = mock(f);
  await runMock(m);
  assert.equal(m.statuses.find(status => status.context === 'risk-gate').state, 'success');
  assert.equal(m.failures.length, 0);
});

test('the last status slot is reserved for a blocking state', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.statuses = Array.from({ length: 999 }, () => ({ context: 'risk-gate', state: 'success',
    description: 'Old success', creator: { id: 41898282, login: 'github-actions[bot]' } }));
  const m = mock(f);
  const result = await runMock(m);
  const writes = m.statuses.filter(status => status.context === 'risk-gate');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].state, 'error');
  assert.match(writes[0].description, /status limit/);
  assert.equal(m.failures.length, 1);
  assert.deepEqual(result.failures.map(item => item.message), ['STATUS_LIMIT']);
});

test('an exhausted context reports failure and never claims publication', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.statuses = Array.from({ length: 1000 }, () => ({ context: 'risk-gate', state: 'success',
    description: 'Old success', creator: { id: 41898282, login: 'github-actions[bot]' } }));
  const m = mock(f);
  await runMock(m);
  assert.equal(m.statuses.filter(status => status.context === 'risk-gate').length, 0);
  assert.equal(m.failures.length, 1);
  assert.equal(f.snapshot.statuses.find(status => status.context === 'risk-gate').state, 'success');
});

// ------------------------------------------------------------- integrity ---

for (const field of ['head', 'base', 'body', 'evidence', 'thread', 'labels', 'policy']) {
  test(`a concurrent ${field} change during evaluation publishes only errors`, async () => {
    const f = receiptMarker(fixture());
    const m = mock(f);
    let reads = 0;
    const get = m.github.rest.pulls.get;
    m.github.rest.pulls.get = async () => {
      if (++reads === 3) {
        if (field === 'head') m.state.pull.head = { sha: 'e'.repeat(40) };
        if (field === 'base') m.state.pull.base = { ...m.state.pull.base, sha: 'e'.repeat(40) };
        if (field === 'body') m.state.pull.body = 'changed during evaluation';
        if (field === 'evidence') f.snapshot.comments[0].updated_at = new Date((NOW + 30) * 1000).toISOString();
        if (field === 'thread') f.snapshot.threads.push({ id: 'PRRT_late', isResolved: false, author: { login: 'chatgpt-codex-connector' } });
        if (field === 'labels') m.state.pull.labels = [{ name: 'owner-approved' }];
        if (field === 'policy') m.state.branch = 'f'.repeat(40);
      }
      return get();
    };
    await runMock(m);
    assert.ok(m.statuses.some(status => status.state === 'error'), 'an error status must be published');
    assert.ok(m.statuses.every(status => status.state !== 'success'), 'no success may be published');
    assert.equal(m.failures.length, 1);
  });
}

test('an unavailable API publishes errors and never a success', async () => {
  const m = mock(fixture());
  m.github.paginate = async () => { throw new Error('API unavailable'); };
  await runMock(m);
  assert.ok(m.statuses.some(status => status.state === 'error'));
  assert.ok(m.statuses.every(status => status.state !== 'success'));
  assert.equal(m.failures.length, 1);
});

test('a policy that cannot be read marks every target and fails', async () => {
  const f = receiptMarker(fixture());
  const m = mock(f);
  const policy = gate.evaluate(f.snapshot, f.policy, POLICY_SHA, NOW);
  assert.equal(policy.allowed, true);
  const result = await runMock(m, { policy: null, policySha: null });
  assert.deepEqual(states(m), [['pr-template', 'error'], ['ai-review', 'error'], ['risk-gate', 'error']]);
  assert.ok(m.statuses.every(status => /policy unavailable/i.test(status.description)));
  assert.equal(m.failures.length, 1);
  assert.deepEqual(result.failures.map(item => item.message), ['policy unavailable']);
});

// ------------------------------------------------------------------ modes ---

test('local mode evaluates and claims nothing', async () => {
  const f = receiptMarker(fixture());
  const policy = { ...POLICY, mode: 'local' };
  const m = mock(f);
  await runMock(m, { policy });
  assert.deepEqual(m.statuses, []);
  assert.equal(m.failures.length, 0);
  assert.match(m.summary.join('\n'), /allowed/);
});

test('report only mode publishes advisory statuses and never fails the run', async () => {
  const f = receiptMarker(fixture());
  f.snapshot.pr.body = 'Nothing useful.';
  const m = mock(f);
  await runMock(m, { policy: { ...POLICY, mode: 'report-only' } });
  assert.equal(m.statuses.length, 3);
  assert.ok(m.statuses.every(status => status.description.startsWith('report-only: ')));
  assert.equal(m.failures.length, 0);
  assert.equal(m.warnings.length, 1);
});

// -------------------------------------------------------------- disclosure ---

test('no comment body is echoed into a status or the summary', async () => {
  const f = receiptMarker(fixture());
  const marker = 'SECRET-PROSE-THAT-MUST-NOT-APPEAR';
  f.snapshot.comments[0].body += `\n${marker}\n`;
  const m = mock(f);
  await runMock(m);
  const exposed = JSON.stringify([m.statuses, m.summary, m.failures, m.warnings, m.infos]);
  assert.equal(exposed.includes(marker), false);
});

test('labels bound to a stale head are reported in the summary, not trusted', async () => {
  const f = receiptMarker(fixture({ path: 'config/settings.json' }));
  const record = labelEvent(f);
  clearRecord(f, record);
  const m = mock(f);
  await runMock(m);
  assert.equal(m.statuses.find(status => status.context === 'risk-gate').state, 'success');
  assert.match(m.summary.join('\n'), /cleared by owner-approved/);
});

test('the runner reports every failing pull request once at the end of a sweep', async () => {
  const f = fixture();
  const m = mock(f, { eventName: 'schedule', open: [{ number: 42, head: { sha: HEAD } }, { number: 43, head: { sha: HEAD } }] });
  m.context.payload = {};
  const evaluated = new Set();
  const get = m.github.rest.pulls.get;
  m.github.rest.pulls.get = async input => { evaluated.add(input.pull_number); return get(input); };
  await runMock(m);
  assert.deepEqual([...evaluated].sort(), [42, 43]);
  assert.equal(m.failures.length, 1);
  assert.match(m.failures[0], /#42, #43/);
});

test('a failing status publication does not abort later pull requests', async () => {
  const f = fixture();
  const m = mock(f, { eventName: 'schedule', open: [{ number: 42, head: { sha: HEAD } }, { number: 43, head: { sha: HEAD } }] });
  m.context.payload = {};
  const evaluated = new Set();
  const get = m.github.rest.pulls.get;
  m.github.rest.pulls.get = async input => { evaluated.add(input.pull_number); return get(input); };
  m.github.rest.repos.createCommitStatus = async input => {
    m.statuses.push(input);
    throw new Error('statuses unavailable');
  };
  await runMock(m);
  assert.deepEqual([...evaluated].sort(), [42, 43]);
  assert.equal(m.failures.length, 1);
});
