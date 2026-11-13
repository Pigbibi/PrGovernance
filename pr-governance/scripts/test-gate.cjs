'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const gate = require('./gate.cjs');
const {
  fixture, receiptMarker, stateMarker, thread, labelEvent, clearRecord, rawComment,
  HEAD, BASE, POLICY_SHA, NOW, COMPLETE_TEMPLATE,
} = require('./fixtures.cjs');

const evaluate = f => gate.evaluate(f.snapshot, f.policy, POLICY_SHA, NOW);

test('sha256 matches node:crypto for ascii, unicode and empty input', () => {
  for (const text of ['', 'abc', 'hello world', '中文 🇨🇳 测试', 'x'.repeat(4096), '\u0000\u00ff']) {
    assert.equal(gate.sha256Hex(text), createHash('sha256').update(text, 'utf8').digest('hex'));
  }
});

test('digest is stable under key order and exposes no undefined leaves', () => {
  assert.equal(gate.digest({ b: 1, a: [2, { d: 3, c: 4 }] }), gate.digest({ a: [2, { c: 4, d: 3 }], b: 1 }));
  assert.match(gate.digest({ omitted: undefined }), /^[a-f0-9]{64}$/);
  assert.equal(gate.canonical({ z: 1, y: 'two' }), '{"y":"two","z":1}');
});

test('the shipped default policy validates', () => {
  const shipped = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'policy.default.json'), 'utf8'));
  assert.deepEqual(gate.validatePolicy(shipped), shipped);
  assert.equal(shipped.version, 'pr-governance/v3');
  assert.equal(shipped.mode, 'enforce');
  assert.equal(shipped.reviewer.provider, 'codex');
  assert.equal(shipped.reviewers, undefined);
  assert.equal(shipped.review_routing.dispatch_mentions[0], '@codex review');
});

test('the owner is optional and resolved from protected variables', () => {
  const shipped = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'policy.default.json'), 'utf8'));
  assert.equal(shipped.owner, undefined);
  const withOwner = { ...shipped, owner: { user_id: 101, login: 'synthetic-owner' } };
  assert.deepEqual(gate.validatePolicy(withOwner), withOwner);
});

test('the schema file lists exactly the fields the evaluator enforces', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'policy.schema.json'), 'utf8'));
  assert.equal(schema.$id, 'pr-governance/v3');
  assert.equal(schema.additionalProperties, false);
  const declared = Object.keys(schema.properties).sort();
  const validated = ['version', 'mode', 'reviewer', 'r0_paths', 'r2_paths',
    'dependabot_template_exemption', 'max_evidence_age_hours'].sort();
  assert.deepEqual(declared, [...validated, 'owner', 'reviewers', 'review_routing'].sort());
  assert.deepEqual([...schema.required].sort(), validated);
  assert.deepEqual([...schema.properties.mode.enum].sort(), ['enforce', 'local', 'report-only']);
  assert.deepEqual(schema.properties.reviewer.required.sort(), ['app_id', 'login', 'provider', 'user_id']);
  assert.deepEqual(schema.properties.owner.required.sort(), ['login', 'user_id']);
});

for (const [name, mutate] of [
  ['wrong schema version', policy => { policy.version = 'pr-governance/v2'; }],
  ['unknown mode', policy => { policy.mode = 'advisory'; }],
  ['missing reviewer login', policy => { delete policy.reviewer.login; }],
  ['extra reviewer field', policy => { policy.reviewer.app_slug = 'synthetic'; }],
  ['unknown top level field', policy => { policy.repository = 'example-org/example-repo'; }],
  ['non bot reviewer login', policy => { policy.reviewer.login = 'some-user'; }],
  ['string owner id', policy => { policy.owner.user_id = '101'; }],
  ['unknown owner field', policy => { policy.owner.team = 'synthetic'; }],
  ['empty owner login', policy => { policy.owner.login = ''; }],
  ['unsupported provider', policy => { policy.reviewer.provider = 'coderabbit'; }],
  ['duplicate r2 rule', policy => { policy.r2_paths.push(policy.r2_paths[0]); }],
  ['absolute r0 rule', policy => { policy.r0_paths.push('/etc/passwd'); }],
  ['escaping r2 rule', policy => { policy.r2_paths.push('../secrets'); }],
  ['non boolean dependabot flag', policy => { policy.dependabot_template_exemption = 'yes'; }],
  ['zero evidence age', policy => { policy.max_evidence_age_hours = 0; }],
  ['excessive evidence age', policy => { policy.max_evidence_age_hours = 100000; }],
]) test(`policy validation rejects ${name}`, () => {
  const f = fixture();
  mutate(f.policy);
  assert.throws(() => evaluate(f));
});

test('protected paths are R2 and prose allowlisted paths are R0', () => {
  const policy = fixture().policy;
  for (const file of ['.github/workflows/ci.yml', '.github/scripts/tool.py', '.github/governance/policy.json',
    'config/app.json', 'settings/prod.yaml', 'deploy/release.sh', 'src/trading/engine.js', 'lib/secrets.js',
    'src/credentials.json', 'iam/policy.json', 'runtime/boot.js', 'strategies/momentum.py', 'Dockerfile',
    'infra/main.tf', 'infra/key.pem', 'package.json', 'requirements-dev.txt', 'CODEOWNERS', 'AGENTS.md',
    'scripts/verify-release.sh', '.env.production']) {
    assert.equal(gate.pathTier(file, policy), 'R2', file);
  }
  assert.equal(gate.pathTier('README.md', policy), 'R0');
  assert.equal(gate.pathTier('docs/prose/notes.md', policy), 'R0');
});

test('unlisted prose and ordinary code default to R1', () => {
  const policy = fixture().policy;
  assert.equal(gate.pathTier('docs/architecture.md', policy), 'R1');
  assert.equal(gate.pathTier('src/view.js', policy), 'R1');
  assert.equal(gate.pathTier('README.txt', policy), 'R1');
});

test('path traversal and absolute paths are refused', () => {
  const policy = fixture().policy;
  for (const file of ['../README.md', '/etc/passwd', 'a/./b', 'a//b', 'a\\b', '']) {
    assert.throws(() => gate.pathTier(file, policy), /Unknown path/, file);
  }
});

test('the highest tier of a change wins', () => {
  const f = fixture({ files: [
    { filename: 'README.md', status: 'modified', sha: 'd'.repeat(40), additions: 1, deletions: 1, patch: '@@ -1 +1 @@\n-old\n+new prose' },
    { filename: 'src/login.js', status: 'modified', sha: 'e'.repeat(40), additions: 1, deletions: 1, patch: '@@ -1 +1 @@\n-a\n+b' },
  ] });
  const result = evaluate(f);
  assert.equal(result.tier, 'R2');
  assert.deepEqual(result.rules.map(rule => rule.tier), ['R0', 'R2']);
});

test('a rename keeps both the old and the new path in the tier', () => {
  const f = fixture({ path: 'docs/prose/moved.md' });
  Object.assign(f.snapshot.files[0], { status: 'renamed', previous_filename: 'iam/policy.json',
    additions: 0, deletions: 0, patch: '' });
  assert.equal(evaluate(f).tier, 'R2');
});

test('prose that carries code or a sensitive keyword is not low risk', () => {
  const code = fixture({ path: 'README.md' });
  code.snapshot.files[0].patch = '@@ -1 +1 @@\n-before\n+`npm install`';
  assert.equal(evaluate(code).tier, 'R1');
  const secret = fixture({ path: 'README.md' });
  secret.snapshot.files[0].patch = '@@ -1 +1 @@\n-before\n+Rotate the deployment credential';
  assert.equal(evaluate(secret).tier, 'R2');
  const chinese = fixture({ path: 'README.md' });
  chinese.snapshot.files[0].patch = '@@ -1 +1 @@\n-before\n+更新部署流程';
  assert.equal(evaluate(chinese).tier, 'R2');
});

test('index-only prose edits still need a reviewer', () => {
  const f = fixture({ path: 'README.md' });
  Object.assign(f.snapshot.files[0], { status: 'added', additions: 1, deletions: 0,
    patch: '@@ -0,0 +1 @@\n+A brand new paragraph.' });
  assert.equal(evaluate(f).tier, 'R1');
});

for (const [name, mutate] of [
  ['incomplete file list', s => { s.pr.changed_files = 2; }],
  ['missing patch', s => { delete s.files[0].patch; }],
  ['truncated patch', s => { s.files[0].additions = 2; }],
  ['binary diff', s => { Object.assign(s.files[0], { patch: '', additions: 0, deletions: 0 }); }],
  ['missing old rename path', s => { s.files[0].status = 'renamed'; }],
  ['unknown file state', s => { s.files[0].status = 'unknown'; }],
  ['duplicate file', s => { s.files.push({ ...s.files[0] }); s.pr.changed_files = 2; }],
  ['missing file sha', s => { s.files[0].sha = ''; }],
  ['incomplete commit coverage', s => { s.pr.commits = 2; }],
  ['incomplete snapshot', s => { s.complete = false; }],
  ['closed pull request', s => { s.pr.state = 'closed'; }],
  ['unknown head', s => { s.pr.head.sha = ''; }],
  ['missing evidence lists', s => { delete s.threads; }],
]) test(`${name} fails closed`, () => {
  const f = fixture();
  mutate(f.snapshot);
  assert.throws(() => evaluate(f));
});

test('the file API cap is refused even when the count matches', () => {
  const f = fixture({ path: 'src/view.js' });
  f.snapshot.files = Array.from({ length: 3000 }, (_, index) => ({
    ...f.snapshot.files[0], filename: `src/${index}.js`,
  }));
  f.snapshot.pr.changed_files = 3000;
  assert.throws(() => evaluate(f), /Incomplete file list/);
});

test('an unknown policy digest is refused', () => {
  const f = fixture();
  assert.throws(() => gate.evaluate(f.snapshot, f.policy, 'not-a-digest', NOW));
});

test('a clean receipt passes R1 and publishes three success statuses', () => {
  const f = receiptMarker(fixture());
  const result = evaluate(f);
  assert.equal(result.allowed, true);
  assert.equal(result.reason, 'review_complete');
  assert.equal(result.tier, 'R1');
  assert.deepEqual(result.statuses.map(entry => [entry.context, entry.state]), [
    ['pr-template', 'success'], ['ai-review', 'success'], ['risk-gate', 'success'],
  ]);
  assert.equal(result.binding.head_sha, HEAD);
  assert.equal(result.binding.base_sha, BASE);
  assert.equal(result.binding.policy_sha256, POLICY_SHA);
  assert.match(result.evidence_sha256, /^[a-f0-9]{64}$/);
});

test('R0 prose still needs the current-head reviewer receipt', () => {
  const missing = evaluate(fixture({ path: 'README.md' }));
  assert.equal(missing.tier, 'R0');
  assert.equal(missing.allowed, false);
  assert.equal(missing.reason, 'ai_review_pending');
  const reviewed = evaluate(receiptMarker(fixture({ path: 'README.md' })));
  assert.equal(reviewed.allowed, true);
  assert.equal(reviewed.review.state, 'success');
  assert.deepEqual(reviewed.statuses.map(entry => entry.context), ['pr-template', 'ai-review', 'risk-gate']);
});

test('R1 without any reviewer marker stays pending', () => {
  const result = evaluate(fixture());
  assert.equal(result.allowed, false);
  assert.equal(result.review.state, 'pending');
  assert.equal(result.reason, 'ai_review_pending');
  assert.deepEqual(result.statuses.map(entry => [entry.context, entry.state]), [
    ['pr-template', 'success'], ['ai-review', 'pending'], ['risk-gate', 'pending'],
  ]);
});

test('high risk needs a clearing label even when the review is clean', () => {
  const f = receiptMarker(fixture({ path: 'config/app.json' }));
  const result = evaluate(f);
  assert.equal(result.tier, 'R2');
  assert.equal(result.allowed, false);
  assert.equal(result.reason, 'clearing_label_required');
  assert.equal(result.statuses.at(-1).state, 'failure');
});

test('a bound owner label clears high risk and names the human approval', () => {
  const f = receiptMarker(fixture({ path: 'config/app.json' }));
  const record = labelEvent(f);
  clearRecord(f, record);
  const result = evaluate(f);
  assert.equal(result.allowed, true);
  assert.equal(result.labels.applied, 'owner');
  assert.match(result.statuses.at(-1).description, /cleared by owner-approved/);
});

test('a bound agent label clears high risk and names the agent approval', () => {
  const f = receiptMarker(fixture({ path: 'config/app.json' }));
  const record = labelEvent(f, { name: 'agent-approved', actor: { id: 999, login: 'agent' } });
  clearRecord(f, record);
  const result = evaluate(f);
  assert.equal(result.allowed, true);
  assert.equal(result.labels.applied, 'agent');
  assert.equal(result.labels.records['agent-approved'].actor_id, 999);
});

test('an incomplete template blocks the verdict', () => {
  const f = receiptMarker(fixture());
  f.snapshot.pr.body = '## What changed\nSomething.\n## How verified\nTests.';
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.reason, 'pr_template_incomplete');
  assert.deepEqual(result.statuses.map(entry => [entry.context, entry.state]), [
    ['pr-template', 'failure'], ['ai-review', 'success'], ['risk-gate', 'failure'],
  ]);
});

test('an unresolved reviewer thread blocks a clean receipt', () => {
  const f = receiptMarker(fixture());
  thread(f, { id: 'PRRT_kwDO_block' });
  const result = evaluate(f);
  assert.equal(result.allowed, false);
  assert.equal(result.review.state, 'failure');
  assert.equal(result.review.reason, 'review_threads');
  assert.deepEqual(result.blocking_findings, ['thread:PRRT_kwDO_block']);
  assert.equal(result.statuses.find(entry => entry.context === 'ai-review').state, 'failure');
});

test('stable thread ids are part of the evidence digest', () => {
  const first = fixture();
  thread(first, { id: 'PRRT_one', resolved: true });
  const second = fixture();
  thread(second, { id: 'PRRT_two', resolved: true });
  assert.notEqual(evaluate(first).evidence_sha256, evaluate(second).evidence_sha256);
  const resolved = fixture();
  thread(resolved, { id: 'PRRT_one', resolved: true });
  assert.equal(evaluate(first).evidence_sha256, evaluate(resolved).evidence_sha256);
});

test('comment prose never enters the evidence digest', () => {
  const first = fixture();
  receiptMarker(first, {}, { updated: -60 });
  const second = fixture();
  receiptMarker(second, {}, { updated: -60 });
  second.snapshot.comments[0].body = '<!-- codex-review-receipt:v1 '
    + JSON.stringify({ review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0 } })
    + ' -->\n\nCompletely different prose that must not be hashed.\n';
  assert.equal(evaluate(first).evidence_sha256, evaluate(second).evidence_sha256);
});

test('template detection accepts English and Chinese headings', () => {
  assert.equal(gate.completeTemplate(COMPLETE_TEMPLATE), true);
  assert.equal(gate.completeTemplate('## AI 使用情况\n使用了智能体。\n## 变更\n修复门禁。\n## 测试\n离线测试通过。'), true);
  assert.equal(gate.completeTemplate('## 模型\nCodex。\n## 这个 PR 做了什么\n修复门禁。\n## 怎么验证的\n离线测试通过。'), true);
  assert.equal(gate.completeTemplate('## AI\nCodex.\n## Summary\nGate fix.\n## Verification\nOffline tests passed.'), true);
  assert.equal(gate.completeTemplate('## AI\nCodex.\n## What changed\nTODO\n## How verified\nOffline tests passed.'), false);
  assert.equal(gate.completeTemplate('## AI\nCodex.\n## What changed\nplaceholder\n## How verified\nTBD'), false);
  assert.equal(gate.completeTemplate('## AI\nCodex.\n## What changed\nValid detail.\n## How verified\n\n  '), false);
  assert.equal(gate.completeTemplate('## Main changes and tests\nEverything is complete.'), false);
  assert.equal(gate.completeTemplate(''), false);
});

test('template comments cannot manufacture or hide headings', () => {
  assert.equal(gate.completeTemplate('## AI\nCodex.\n<!-- unfinished\n## What changed\nHidden.\n## How verified\nHidden.'), false);
  assert.equal(gate.completeTemplate('## AI\nCodex.\n## W<!-- removed -->hat changed\nDetail.\n## How verified\nDetail.'), false);
  assert.equal(gate.completeTemplate('## AI\nCodex.\n<!-- ## What changed\nHidden. -->\n## How verified\nDetail.'), false);
});

test('dependabot detection requires bot author, web-flow committer and a verified commit', () => {
  const commits = [{ author: { login: 'dependabot[bot]' }, committer: { login: 'web-flow' },
    commit: { verification: { verified: true } } }];
  const identity = login => ({ id: 49699333, login, type: 'Bot' });
  const build = mutate => {
    const f = fixture({ commits, dependabotPolicy: { action_files: ['.github/workflows/ci.yml'] } });
    f.snapshot.pr.user = identity('dependabot[bot]');
    mutate?.(f.snapshot);
    return f;
  };
  assert.equal(gate.dependabotEvidence(build().snapshot, build().policy).detected, true);
  for (const mutate of [
    snapshot => { snapshot.commits[0].committer.login = 'author'; },
    snapshot => { snapshot.commits[0].commit.verification.verified = false; },
    snapshot => { snapshot.commits[0].author.login = 'author'; },
    snapshot => { snapshot.pr.user = { id: 7, login: 'author' }; },
    snapshot => { snapshot.commits = []; snapshot.pr.commits = 0; },
  ]) {
    const f = build(mutate);
    assert.equal(gate.dependabotEvidence(f.snapshot, f.policy).detected, false);
  }
});

test('an allowlisted action bump is not high risk, a different workflow still is', () => {
  const bump = path => ({ filename: path, status: 'modified', sha: 'd'.repeat(40), additions: 1, deletions: 1,
    patch: '@@ -1 +1 @@\n-      - uses: actions/checkout@v5\n+      - uses: actions/checkout@v6' });
  const commits = [{ author: { login: 'dependabot[bot]' }, committer: { login: 'web-flow' },
    commit: { verification: { verified: true } } }];
  const build = files => {
    const f = fixture({ files, commits });
    f.snapshot.pr.user = { id: 49699333, login: 'dependabot[bot]', type: 'Bot' };
    f.snapshot.dependabotPolicy = { action_files: ['.github/workflows/ci.yml'] };
    return f;
  };
  const allowed = build([bump('.github/workflows/ci.yml')]);
  assert.equal(evaluate(allowed).tier, 'R1');
  const other = build([bump('.github/workflows/release.yml')]);
  assert.equal(evaluate(other).tier, 'R2');
  const swapped = build([{ filename: '.github/workflows/ci.yml', status: 'modified', sha: 'd'.repeat(40),
    additions: 1, deletions: 1, patch: '@@ -1 +1 @@\n-      - uses: actions/checkout@v5\n+      - uses: evil/action@v6' }]);
  assert.equal(evaluate(swapped).tier, 'R2');
  const extra = build([{ filename: '.github/workflows/ci.yml', status: 'modified', sha: 'd'.repeat(40),
    additions: 2, deletions: 1,
    patch: '@@ -1,2 +1,2 @@\n-      - uses: actions/checkout@v5\n+      - uses: actions/checkout@v6\n+      if: false' }]);
  assert.equal(evaluate(extra).tier, 'R2');
  const human = build([bump('.github/workflows/ci.yml')]);
  human.snapshot.pr.user = { id: 7, login: 'author' };
  assert.equal(evaluate(human).tier, 'R2');
});

test('Dependabot template exemption follows the policy flag', () => {
  const commits = [{ author: { login: 'dependabot[bot]' }, committer: { login: 'web-flow' },
    commit: { verification: { verified: true } } }];
  const build = flag => {
    const f = fixture({ commits, body: 'Automated dependency bump.', policy: policy => {
      policy.dependabot_template_exemption = flag;
    } });
    f.snapshot.pr.user = { id: 49699333, login: 'dependabot[bot]', type: 'Bot' };
    return receiptMarker(f);
  };
  assert.equal(evaluate(build(true)).template.exempt, true);
  assert.equal(evaluate(build(true)).allowed, true);
  assert.equal(evaluate(build(false)).template.ok, false);
  assert.equal(evaluate(build(false)).allowed, false);
});

test('a pull request author never influences the verdict outside Dependabot detection', () => {
  for (const login of ['author', 'agent', 'someone-else']) {
    const f = receiptMarker(fixture({ path: 'config/app.json' }));
    f.snapshot.pr.user = { id: 11, login };
    assert.equal(evaluate(f).allowed, false);
    assert.equal(evaluate(f).reason, 'clearing_label_required');
  }
});

test('the mode is carried into the result without changing the verdict', () => {
  for (const mode of ['enforce', 'local', 'report-only']) {
    const f = receiptMarker(fixture(), {}, {});
    f.policy.mode = mode;
    assert.equal(evaluate(f).mode, mode);
    assert.equal(evaluate(f).allowed, true);
  }
});

test('a fallback claude receipt satisfies ai-review when configured', () => {
  const f = fixture();
  const claude = { provider: 'claude', app_id: 1236702, user_id: 209825114, login: 'claude[bot]' };
  f.policy.reviewers = [f.policy.reviewer, claude];
  rawComment(f, `<!-- codex-review-state:v1 ${JSON.stringify({
    code_review: { commit_sha: HEAD, status: 'completed', has_unresolved_findings: false },
    security_review: {},
  })} -->`, { user: { id: claude.user_id, login: claude.login, type: 'Bot' } });
  const result = evaluate(f);
  assert.equal(result.review.state, 'success');
  assert.equal(result.review.provider, 'claude');
});

test('ai-review-receipt is accepted from any configured reviewer', () => {
  const f = fixture();
  const cursor = { provider: 'cursor', app_id: 1210556, user_id: 206951365, login: 'cursor[bot]' };
  f.policy.reviewers = [f.policy.reviewer, cursor];
  rawComment(f, `<!-- ai-review-receipt:v1 ${JSON.stringify({
    review: { provider: 'cursor', commit_sha: HEAD, coverage: 'complete', unresolved_findings: false },
  })} -->`, { user: { id: cursor.user_id, login: cursor.login, type: 'Bot' } });
  const result = evaluate(f);
  assert.equal(result.review.state, 'success');
  assert.equal(result.review.provider, 'cursor');
});
