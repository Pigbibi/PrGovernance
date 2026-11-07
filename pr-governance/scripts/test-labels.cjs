'use strict';

// Label evidence. A label lives on the pull request, not on a commit, so the
// only label that counts is one whose authenticated timeline event is still the
// newest event for that label and whose head-bound record says so.

const test = require('node:test');
const assert = require('node:assert/strict');
const gate = require('./gate.cjs');
const runner = require('./runner.cjs');
const { fixture, receiptMarker, labelEvent, clearRecord, HEAD, POLICY_SHA, NOW } = require('./fixtures.cjs');

const evaluate = f => gate.evaluate(f.snapshot, f.policy, POLICY_SHA, NOW);
const highRisk = () => receiptMarker(fixture({ path: 'config/settings.json' }));

test('an owner label added by the owner and bound to the head clears high risk', () => {
  const f = highRisk();
  const record = labelEvent(f);
  clearRecord(f, record);
  const result = evaluate(f);
  assert.equal(result.allowed, true);
  assert.equal(result.labels.applied, 'owner');
  assert.deepEqual(result.labels.records['owner-approved'], { event_id: record.id,
    actor_id: f.policy.owner.user_id, actor_login: f.policy.owner.login });
});

test('an owner-approved label from another actor never counts', () => {
  const f = highRisk();
  const record = labelEvent(f, { actor: { id: 5, login: 'author' } });
  clearRecord(f, record);
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.labels.applied, null);
  assert.equal(result.reason, 'clearing_label_required');
});

test('an owner login with the wrong numeric id never counts', () => {
  const f = highRisk();
  const record = labelEvent(f, { actor: { id: 5, login: f.policy.owner.login } });
  clearRecord(f, record);
  assert.equal(evaluate(f).labels.applied, null);
});

test('an agent label counts from any actor and records who added it', () => {
  for (const actor of [{ id: 5, login: 'author' }, { id: 4242, login: 'some-agent[bot]' }]) {
    const f = highRisk();
    const record = labelEvent(f, { name: 'agent-approved', actor });
    clearRecord(f, record);
    const result = evaluate(f);
    assert.equal(result.allowed, true);
    assert.equal(result.labels.applied, 'agent');
    assert.deepEqual(result.labels.records['agent-approved'], { event_id: record.id,
      actor_id: actor.id, actor_login: actor.login });
    assert.match(result.statuses.at(-1).description, /cleared by agent-approved, NOT confirmed by the owner/);
  }
});

test('a label without a head-bound record never clears high risk', () => {
  const f = highRisk();
  labelEvent(f);
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.labels.applied, null);
});

test('a record for a different event does not revive a re-added label', () => {
  const f = highRisk();
  const first = labelEvent(f, { id: 5000 });
  clearRecord(f, first);
  labelEvent(f, { id: 5001, event: 'unlabeled' });
  const second = labelEvent(f, { id: 5002 });
  assert.equal(evaluate(f).labels.applied, null);
  clearRecord(f, second);
  assert.equal(evaluate(f).labels.applied, 'owner');
});

test('a revoked label stays revoked even with its old record present', () => {
  const f = highRisk();
  const record = labelEvent(f);
  clearRecord(f, record);
  labelEvent(f, { id: 6000, event: 'unlabeled' });
  assert.equal(evaluate(f).labels.applied, null);
  assert.equal(evaluate(f).allowed, false);
});

test('a label event that is not the newest for that label is ignored', () => {
  const f = highRisk();
  const stale = labelEvent(f, { id: 4999, name: 'agent-approved', actor: { id: 5, login: 'author' } });
  clearRecord(f, stale);
  labelEvent(f, { id: 5001, name: 'agent-approved', event: 'unlabeled' });
  assert.equal(evaluate(f).labels.applied, null);
});

test('a record that names another pull request does not bind', () => {
  const f = highRisk();
  const record = labelEvent(f);
  clearRecord(f, record, { description: `${record.name} for PR 7 at event ${record.id} on this head` });
  assert.equal(evaluate(f).labels.applied, null);
});

test('a failing clearing-label status does not bind', () => {
  const f = highRisk();
  const record = labelEvent(f);
  clearRecord(f, record);
  f.snapshot.statuses[0].state = 'failure';
  assert.equal(evaluate(f).labels.applied, null);
});

test('a label left on the pull request without any timeline event does not bind', () => {
  const f = highRisk();
  f.snapshot.pr.labels = [{ name: 'owner-approved' }];
  f.snapshot.statuses.push({ context: 'clearing-label', state: 'success',
    description: `owner-approved for PR 42 at event 1 on this head` });
  assert.equal(evaluate(f).labels.applied, null);
});

test('a bound owner label outranks a bound agent label on the same head', () => {
  const f = highRisk();
  const owner = labelEvent(f, { id: 5000, name: 'owner-approved' });
  clearRecord(f, owner);
  const agent = labelEvent(f, { id: 5001, name: 'agent-approved', actor: { id: 5, login: 'author' } });
  clearRecord(f, agent);
  assert.equal(evaluate(f).labels.applied, 'owner');
});

test('a bound agent label still clears high risk when the owner label is unbound', () => {
  const f = highRisk();
  labelEvent(f, { id: 5000, name: 'owner-approved' });
  const agent = labelEvent(f, { id: 5001, name: 'agent-approved', actor: { id: 5, login: 'author' } });
  clearRecord(f, agent);
  const result = evaluate(f);
  assert.equal(result.allowed, true);
  assert.equal(result.labels.applied, 'agent');
});

test('no label bypasses the review requirement', () => {
  const f = fixture({ path: 'config/settings.json' });
  const record = labelEvent(f);
  clearRecord(f, record);
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.reason, 'ai_review_pending');
  assert.equal(result.statuses.find(entry => entry.context === 'ai-review').state, 'pending');
  assert.equal(result.statuses.find(entry => entry.context === 'risk-gate').state, 'pending');
});

test('no label bypasses an unresolved reviewer thread', () => {
  const f = highRisk();
  const record = labelEvent(f);
  clearRecord(f, record);
  f.snapshot.threads.push({ id: 'PRRT_open', isResolved: false, isOutdated: false,
    author: { login: f.policy.reviewer.login } });
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.review.reason, 'review_threads');
});

test('no label bypasses the pull request template', () => {
  const f = highRisk();
  f.snapshot.pr.body = 'Nothing useful here.';
  const record = labelEvent(f);
  clearRecord(f, record);
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.reason, 'pr_template_incomplete');
  assert.equal(result.statuses.find(entry => entry.context === 'risk-gate').state, 'failure');
});

test('low risk needs no label, so an unbound label changes nothing', () => {
  const withLabel = receiptMarker(fixture({ path: 'src/view.js' }));
  labelEvent(withLabel);
  const withoutLabel = receiptMarker(fixture({ path: 'src/view.js' }));
  assert.equal(evaluate(withLabel).allowed, true);
  assert.equal(evaluate(withLabel).evidence_sha256, evaluate(withoutLabel).evidence_sha256);
});

// ------------------------------------------------------------ record step ---

function recordContext(mutate = () => {}) {
  const context = {
    eventName: 'pull_request_target',
    repo: { owner: 'example-org', repo: 'example-repo' },
    payload: {
      action: 'labeled',
      label: { name: 'owner-approved' },
      pull_request: { number: 42, state: 'open', head: { sha: HEAD }, updated_at: '2026-01-01T00:00:00Z' },
    },
    serverUrl: 'https://github.example',
    runId: 7,
  };
  mutate(context);
  return context;
}

function recordMock(timeline) {
  const statuses = [];
  const github = {
    paginate: async () => timeline,
    rest: {
      issues: { listEvents: 'events' },
      repos: { createCommitStatus: async input => { statuses.push(input); return { data: input }; } },
    },
  };
  const infos = [];
  return { github, core: { info: message => infos.push(message) }, statuses, infos };
}

const event = (overrides = {}) => ({ id: 5000, event: 'labeled', label: { name: 'owner-approved' },
  actor: { id: 20649888, login: 'owner' }, created_at: '2026-01-01T00:00:00Z', ...overrides });

test('the record step writes the exact head-bound description', async () => {
  const m = recordMock([event()]);
  const record = await runner.recordLabel({ github: m.github, context: recordContext(), core: m.core });
  assert.equal(record.event_id, 5000);
  assert.deepEqual(m.statuses, [{
    owner: 'example-org',
    repo: 'example-repo',
    sha: HEAD,
    context: 'clearing-label',
    state: 'success',
    description: 'owner-approved for PR 42 at event 5000 on this head',
    target_url: 'https://github.example/example-org/example-repo/actions/runs/7',
  }]);
  assert.match(m.infos[0], /actor 20649888/);
});

test('the record step accepts an agent label and records its actor', async () => {
  const context = recordContext(context => { context.payload.label = { name: 'agent-approved' }; });
  const m = recordMock([event({ label: { name: 'agent-approved' }, actor: { id: 77, login: 'agent' } })]);
  const record = await runner.recordLabel({ github: m.github, context, core: m.core });
  assert.equal(record.actor_id, 77);
  assert.equal(m.statuses[0].description, 'agent-approved for PR 42 at event 5000 on this head');
});

test('the record step ignores everything that is not a clearing label addition', async () => {
  const cases = [
    recordContext(context => { context.payload.label = { name: 'documentation' }; }),
    recordContext(context => { context.payload.action = 'unlabeled'; }),
    recordContext(context => { context.eventName = 'pull_request'; }),
    recordContext(context => { context.payload.pull_request.state = 'closed'; }),
    recordContext(context => { context.payload.pull_request.head = {}; }),
    recordContext(context => { context.payload.pull_request.updated_at = null; }),
  ];
  for (const context of cases) {
    const m = recordMock([event()]);
    assert.equal(await runner.recordLabel({ github: m.github, context, core: m.core }), null);
    assert.deepEqual(m.statuses, []);
  }
});

test('an ambiguous same-second addition records nothing', async () => {
  const m = recordMock([event(), event({ id: 5001 })]);
  assert.equal(await runner.recordLabel({ github: m.github, context: recordContext(), core: m.core }), null);
  assert.deepEqual(m.statuses, []);
});

test('an addition whose timestamp does not match any event records nothing', async () => {
  const m = recordMock([event({ created_at: '2026-01-01T00:00:09Z' })]);
  assert.equal(await runner.recordLabel({ github: m.github, context: recordContext(), core: m.core }), null);
  assert.deepEqual(m.statuses, []);
});

test('a label event without an actor cannot be recorded', async () => {
  const m = recordMock([event({ actor: {} })]);
  assert.equal(await runner.recordLabel({ github: m.github, context: recordContext(), core: m.core }), null);
  assert.deepEqual(m.statuses, []);
});
