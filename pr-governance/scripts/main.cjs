'use strict';

const gate = require('./gate.cjs');
const { run, recordLabel } = require('./runner.cjs');

const POLICY_PATH = '.github/governance/policy.json';

// Account identities belong in protected configuration, not in committed
// policy files, so the owner is resolved from repository or organization
// variables and only falls back to the policy when none is configured.
function configuredOwner() {
  const raw = process.env.GOVERNANCE_OWNER_ID;
  const login = process.env.GOVERNANCE_OWNER_LOGIN;
  if (!raw && !login) return null;
  const id = Number(raw);
  if (!Number.isSafeInteger(id) || id < 1 || typeof login !== 'string' || !login) {
    throw new Error('Incomplete owner configuration');
  }
  return { user_id: id, login };
}

async function defaultBranch(github, context) {
  const known = context.payload?.repository?.default_branch
    || context.payload?.pull_request?.base?.ref;
  if (known) return known;
  const { data } = await github.rest.repos.get(context.repo);
  return data.default_branch;
}

async function loadPolicy(github, context, branch) {
  const { data: ref } = await github.rest.repos.getBranch({ ...context.repo, branch });
  const policyCommit = ref.commit?.sha;
  if (!gate.isSha(policyCommit)) throw new Error('Unknown policy commit');
  const { data: file } = await github.rest.repos.getContent({
    ...context.repo, path: POLICY_PATH, ref: policyCommit,
  });
  if (file.type !== 'file' || file.encoding !== 'base64' || !file.content) {
    throw new Error('Missing trusted policy');
  }
  let policy;
  try {
    policy = JSON.parse(Buffer.from(file.content, 'base64').toString('utf8'));
  } catch {
    throw new Error('Trusted policy is not valid JSON');
  }
  const owner = configuredOwner();
  if (owner) policy.owner = owner;
  gate.validatePolicy(policy);
  // Without an owner nobody can ever satisfy owner-approved, so a missing
  // configuration must fail the check instead of silently downgrading it.
  if (!policy.owner) throw new Error('Owner configuration is required');
  return { policy, policyCommit, policySha: gate.sha256Hex(gate.canonical(policy)) };
}

async function runGate({ github, context, core }) {
  // Label evidence must not ride on an evaluation a later event can supersede,
  // so its own job records it and stops. The evaluate job depends on this one.
  if (context.eventName === 'pull_request_target' && context.payload?.action === 'labeled') {
    return recordLabel({ github, context, core });
  }
  const branch = await defaultBranch(github, context);
  const { policy, policyCommit, policySha } = await loadPolicy(github, context, branch);
  return run({ github, context, core, policy, policySha, policyCommit, defaultBranch: branch });
}

module.exports = { runGate, loadPolicy, defaultBranch };
