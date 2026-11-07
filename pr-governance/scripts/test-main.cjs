'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const main = require('./main.cjs');

const POLICY = {
  version: 'pr-governance/v3',
  mode: 'enforce',
  reviewer: { provider: 'codex', app_id: 1144995, user_id: 199175422,
    login: 'chatgpt-codex-connector[bot]' },
  r0_paths: [],
  r2_paths: [],
  dependabot_template_exemption: true,
  max_evidence_age_hours: 168,
};

const githubFor = policy => ({
  rest: {
    repos: {
      get: async () => ({ data: { default_branch: 'main' } }),
      getBranch: async () => ({ data: { commit: { sha: 'a'.repeat(40) } } }),
      getContent: async () => ({ data: { type: 'file', encoding: 'base64',
        content: Buffer.from(JSON.stringify(policy)).toString('base64') } }),
    },
  },
});

const context = { repo: { owner: 'example-org', repo: 'example-repo' }, payload: {} };

async function load(policy, environment) {
  const saved = { ...process.env };
  Object.assign(process.env, environment);
  try {
    return await main.loadPolicy(githubFor(policy), context, 'main');
  } finally {
    delete process.env.GOVERNANCE_OWNER_ID;
    delete process.env.GOVERNANCE_OWNER_LOGIN;
    Object.assign(process.env, saved);
  }
}

test('owner configuration replaces a committed owner', async () => {
  const { policy } = await load({ ...POLICY, owner: { user_id: 1, login: 'stale' } },
    { GOVERNANCE_OWNER_ID: '42', GOVERNANCE_OWNER_LOGIN: 'owner' });
  assert.deepEqual(policy.owner, { user_id: 42, login: 'owner' });
});

test('a policy without owner is valid when the variables are set', async () => {
  const { policy, policySha } = await load(POLICY,
    { GOVERNANCE_OWNER_ID: '42', GOVERNANCE_OWNER_LOGIN: 'owner' });
  assert.deepEqual(policy.owner, { user_id: 42, login: 'owner' });
  assert.match(policySha, /^[0-9a-f]{64}$/);
});

test('a policy without owner and without variables fails closed', async () => {
  await assert.rejects(load(POLICY, {}));
});

test('an incomplete owner configuration fails closed', async () => {
  await assert.rejects(load(POLICY, { GOVERNANCE_OWNER_ID: '42' }), /owner configuration/);
  await assert.rejects(load(POLICY,
    { GOVERNANCE_OWNER_ID: '0', GOVERNANCE_OWNER_LOGIN: 'owner' }), /owner configuration/);
});

async function withEnvironment(environment, action) {
  const saved = { ...process.env };
  delete process.env.GOVERNANCE_RECORD_LABEL;
  Object.assign(process.env, environment);
  try {
    return await action();
  } finally {
    delete process.env.GOVERNANCE_RECORD_LABEL;
    Object.assign(process.env, saved);
  }
}

test('recording a label is a separate dispatch path', async () => {
  const written = [];
  const labeled = {
    action: 'labeled',
    label: { name: 'agent-approved' },
    pull_request: { number: 7, state: 'open', updated_at: '2026-01-01T00:00:00Z',
      head: { sha: 'b'.repeat(40) }, base: { ref: 'main' } },
  };
  const github = {
    paginate: async () => [{ id: 11, event: 'labeled', created_at: '2026-01-01T00:00:00Z',
      label: { name: 'agent-approved' }, actor: { id: 42, login: 'agent' } }],
    rest: {
      issues: { listEvents: async () => ({ data: [] }) },
      repos: {
        // Evaluation would need this; the record path must never get here.
        get: async () => { throw new Error('recording must not read the repository'); },
        createCommitStatus: async params => { written.push(params); return { data: params }; },
      },
    },
  };
  const result = await withEnvironment({ GOVERNANCE_RECORD_LABEL: 'true' }, () => main.runGate({
    github, core: { info() {} },
    context: { eventName: 'pull_request_target', repo: { owner: 'example-org', repo: 'example-repo' },
      payload: labeled, serverUrl: 'https://github.example', runId: 9 },
  }));
  assert.equal(result.event_id, 11);
  assert.deepEqual(written.map(item => [item.context, item.state]), [['clearing-label', 'success']]);
});

test('an unreadable policy publishes blocking statuses instead of stale successes', async () => {
  const written = [];
  const failed = [];
  const github = {
    paginate: async (method, params) => (await method(params)).data,
    rest: {
      repos: {
        get: async () => { throw new Error('network'); },
        listCommitStatusesForRef: async () => ({ data: [] }),
        createCommitStatus: async params => { written.push(params); return { data: params }; },
      },
      pulls: {
        get: async () => ({ data: { number: 7, state: 'open', head: { sha: 'b'.repeat(40) },
          base: { ref: 'main' } } }),
        list: async () => ({ data: [] }),
      },
    },
  };
  const result = await withEnvironment({ GOVERNANCE_RECORD_LABEL: 'false' }, () => main.runGate({
    github, core: { warning() {}, setFailed: message => failed.push(message) },
    context: { eventName: 'pull_request_target', repo: { owner: 'example-org', repo: 'example-repo' },
      payload: { action: 'labeled', label: { name: 'agent-approved' },
        pull_request: { number: 7, state: 'open', head: { sha: 'b'.repeat(40) }, base: { ref: 'main' } } },
      serverUrl: 'https://github.example', runId: 9 },
  }));
  assert.deepEqual(result.failures, [{ number: 7, message: 'policy unavailable' }]);
  assert.deepEqual(written.map(item => [item.context, item.state]),
    [['pr-template', 'error'], ['ai-review', 'error'], ['risk-gate', 'error']]);
  assert.equal(failed.length, 1);
});

