'use strict';

// Reviewer evidence reader. Only the configured reviewer identity is read, and
// the newest marker decides: a clean receipt never outlives a newer bad one.

const test = require('node:test');
const assert = require('node:assert/strict');
const gate = require('./gate.cjs');
const { fixture, stateMarker, receiptMarker, rawComment, thread, HEAD, POLICY_SHA, NOW } = require('./fixtures.cjs');

const evaluate = f => gate.evaluate(f.snapshot, f.policy, POLICY_SHA, NOW);
const review = f => evaluate(f).review;

test('a clean receipt-v1 approves the current head', () => {
  const result = evaluate(receiptMarker(fixture()));
  assert.equal(result.allowed, true);
  assert.equal(result.review.format, 'codex-review-receipt:v1');
  assert.equal(result.review.commit_sha, HEAD);
  assert.equal(result.review.coverage, 'complete');
  assert.equal(result.statuses.find(entry => entry.context === 'ai-review').state, 'success');
});

test('a clean state-v1 approves the current head', () => {
  const result = evaluate(stateMarker(fixture()));
  assert.equal(result.allowed, true);
  assert.equal(result.review.format, 'codex-review-state:v1');
  assert.equal(result.review.comment_id, 900);
});

test('a marker for another commit does not approve this head', () => {
  const result = evaluate(receiptMarker(fixture(), { commit_sha: 'f'.repeat(40) }));
  assert.equal(result.allowed, false);
  assert.equal(result.review.reason, 'review_stale');
  assert.equal(result.statuses.find(entry => entry.context === 'ai-review').state, 'failure');
});

test('an unfinished review is pending, not a failure and not a pass', () => {
  const result = evaluate(stateMarker(fixture(), { status: 'in_progress' }));
  assert.equal(result.allowed, false);
  assert.equal(result.review.state, 'pending');
  assert.equal(result.review.reason, 'review_running');
  assert.equal(result.statuses.find(entry => entry.context === 'risk-gate').state, 'pending');
});

test('a missing marker is pending and never a clean review', () => {
  const result = evaluate(fixture());
  assert.equal(result.review.reason, 'review_pending');
  assert.equal(result.review.comment_id, null);
  assert.equal(result.statuses.find(entry => entry.context === 'ai-review').state, 'pending');
});

test('the newest marker wins when the head was reviewed twice', () => {
  const f = receiptMarker(fixture(), { commit_sha: 'f'.repeat(40) }, { updated: -600, id: 901 });
  receiptMarker(f, {}, { updated: -60, id: 902 });
  assert.equal(evaluate(f).allowed, true);
  const reverse = receiptMarker(fixture(), {}, { updated: -600, id: 901 });
  receiptMarker(reverse, { commit_sha: 'f'.repeat(40) }, { updated: -60, id: 902 });
  assert.equal(evaluate(reverse).allowed, false);
});

test('a newer malformed marker supersedes an older clean receipt', () => {
  const f = receiptMarker(fixture(), {}, { updated: -600, id: 901 });
  rawComment(f, '<!-- codex-review-receipt:v1 {not json} -->', { updated: -60, id: 902 });
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.review.reason, 'review_malformed');
  assert.equal(result.review.comment_id, 902);
});

test('a newer marker that names no commit supersedes an older receipt', () => {
  const f = receiptMarker(fixture(), {}, { updated: -600, id: 901 });
  rawComment(f, '<!-- codex-review-state:v1 {"code_review":{}} -->', { updated: -60, id: 902 });
  assert.equal(evaluate(f).review.reason, 'review_malformed');
});

test('two markers in one comment are ambiguous and refused', () => {
  const f = fixture();
  rawComment(f, `<!-- codex-review-receipt:v1 ${JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0 } })} -->`
    + `\n<!-- codex-review-state:v1 ${JSON.stringify({ code_review: { commit_sha: HEAD, status: 'completed', has_unresolved_findings: false } })} -->`);
  assert.equal(evaluate(f).review.reason, 'review_malformed');
});

test('an unterminated second marker is counted and refused', () => {
  const f = fixture();
  rawComment(f, `<!-- codex-review-receipt:v1 ${JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0 } })} -->`
    + '\n<!-- codex-review-state:v1 {"code_review":');
  assert.equal(evaluate(f).review.reason, 'review_malformed');
});

test('a marker written by another account is ignored', () => {
  const f = fixture();
  rawComment(f, `<!-- codex-review-receipt:v1 ${JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0 } })} -->`,
    { user: { id: 999, login: 'impostor[bot]', type: 'Bot' } });
  assert.equal(evaluate(f).review.reason, 'review_pending');
});

test('a marker with the right login but the wrong numeric id is ignored', () => {
  const f = fixture();
  rawComment(f, `<!-- codex-review-receipt:v1 ${JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0 } })} -->`,
    { user: { id: 1, login: f.policy.reviewer.login, type: 'Bot' } });
  assert.equal(evaluate(f).review.reason, 'review_pending');
});

test('reviewer identity is matched with and without the bot suffix', () => {
  const f = fixture();
  rawComment(f, `<!-- codex-review-receipt:v1 ${JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0 } })} -->`,
    { user: { id: f.policy.reviewer.user_id, login: f.policy.reviewer.login.replace('[bot]', ''), type: 'Bot' } });
  assert.equal(evaluate(f).allowed, true);
});

test('unresolved findings in a receipt block and are named', () => {
  for (const unresolved of [true, 3]) {
    const result = evaluate(receiptMarker(fixture(), { unresolved_findings: unresolved }));
    assert.equal(result.allowed, false);
    assert.equal(result.review.reason, 'review_findings');
    assert.deepEqual(result.blocking_findings, ['marker:unresolved_findings']);
  }
});

test('a resolved receipt finding passes without a blocker', () => {
  const result = evaluate(receiptMarker(fixture(), { unresolved_findings: 0 }));
  assert.equal(result.allowed, true);
  assert.deepEqual(result.blocking_findings, []);
});

test('a missing findings flag is not evidence of a clean review', () => {
  const receipt = fixture();
  rawComment(receipt, `<!-- codex-review-receipt:v1 ${JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete' } })} -->`);
  assert.equal(evaluate(receipt).review.reason, 'review_findings_unknown');
  const state = fixture();
  rawComment(state, `<!-- codex-review-state:v1 ${JSON.stringify({ code_review: { commit_sha: HEAD, status: 'completed' } })} -->`);
  assert.equal(evaluate(state).review.reason, 'review_findings_unknown');
});

test('partial or unknown coverage blocks the verdict', () => {
  for (const coverage of ['partial', 'sampled', '']) {
    const result = evaluate(receiptMarker(fixture(), { coverage }));
    assert.equal(result.allowed, false, coverage);
    assert.equal(result.review.reason, 'review_partial', coverage);
  }
});

test('evidence older than the policy age limit is refused', () => {
  const limit = 168 * 3600;
  const stale = evaluate(receiptMarker(fixture(), {}, { updated: -limit - 1 }));
  assert.equal(stale.review.reason, 'review_expired');
  const fresh = evaluate(receiptMarker(fixture(), {}, { updated: -limit + 1 }));
  assert.equal(fresh.allowed, true);
  const future = evaluate(receiptMarker(fixture(), {}, { updated: 600 }));
  assert.equal(future.allowed, true);
});

test('an unresolved thread blocks even when the receipt says clean', () => {
  const f = receiptMarker(fixture());
  thread(f, { id: 'PRRT_1' });
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.review.reason, 'review_threads');
  assert.deepEqual(result.blocking_findings, ['thread:PRRT_1']);
});

test('marker findings and threads are both listed as blockers', () => {
  const f = receiptMarker(fixture(), { unresolved_findings: 2 });
  thread(f, { id: 'PRRT_2' });
  assert.deepEqual(evaluate(f).blocking_findings, ['thread:PRRT_2', 'marker:unresolved_findings']);
});

test('a resolved thread and a human thread never block', () => {
  const resolved = receiptMarker(fixture());
  thread(resolved, { id: 'PRRT_done', resolved: true });
  assert.equal(evaluate(resolved).allowed, true);
  const human = receiptMarker(fixture());
  thread(human, { id: 'PRRT_human', author: 'reviewer-person' });
  assert.equal(evaluate(human).allowed, true);
});

test('a thread author id of another account does not block', () => {
  const f = receiptMarker(fixture());
  thread(f, { id: 'PRRT_fake' });
  Object.assign(f.snapshot.threads[0].author, { id: 1 });
  assert.equal(evaluate(f).allowed, true);
});

test('R0 prose reports no review requirement even with a stale marker', () => {
  const f = receiptMarker(fixture({ path: 'README.md' }), { commit_sha: 'f'.repeat(40) });
  const result = evaluate(f);
  assert.equal(result.tier, 'R0');
  assert.equal(result.review.reason, 'review_not_required');
  assert.equal(result.allowed, true);
});

test('an unresolved thread still blocks R0 prose', () => {
  const f = fixture({ path: 'README.md' });
  thread(f, { id: 'PRRT_prose' });
  assert.equal(evaluate(f).allowed, false);
});

test('a clean receipt does not clear a high-risk change', () => {
  const result = evaluate(receiptMarker(fixture({ path: 'runtime/engine.js' })));
  assert.equal(result.tier, 'R2');
  assert.equal(result.allowed, false);
  assert.equal(result.reason, 'clearing_label_required');
});
