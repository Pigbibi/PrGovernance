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
