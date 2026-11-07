'use strict';

// Synthetic fixtures shared by the test suites. Every identifier is either a
// documented public constant from policy.default.json or an obviously fake one;
// no real credential, comment body or personal data appears here.

const policy = require('../policy.default.json');

const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const POLICY_SHA = 'c'.repeat(64);
const NOW = 1_800_000_000;
const COMPLETE_TEMPLATE = '## AI assistance\nCodex was used for the gate.\n'
  + '## What changed\nBind reviewer evidence to the head.\n'
  + '## How verified\nOffline tests passed.';

const at = (offsetSeconds) => new Date((NOW + offsetSeconds) * 1000).toISOString();

function fixture(options = {}) {
  const clone = structuredClone(policy);
  // The shipped policy leaves the owner to protected variables, so fixtures
  // inject a synthetic one for the label and digest assertions.
  clone.owner ??= { user_id: 101, login: 'synthetic-owner' };
  if (options.policy) options.policy(clone);
  const files = options.files || [{
    filename: options.path || 'src/view.js',
    status: 'modified',
    sha: 'd'.repeat(40),
    additions: 1,
    deletions: 1,
    patch: '@@ -1 +1 @@\n-before\n+after',
  }];
  const commits = options.commits || [{
    author: { id: 7, login: 'author' },
    committer: { id: 7, login: 'author' },
    commit: { verification: { verified: false }, committer: { email: 'author@example.invalid' } },
  }];
  return {
    snapshot: {
      repository: 'example-org/example-repo',
      policyCommit: BASE,
      complete: true,
      pr: {
        state: 'open',
        number: options.number || 42,
        user: { id: 7, login: 'author', type: 'User' },
        body: options.body ?? COMPLETE_TEMPLATE,
        labels: [],
        head: { sha: HEAD },
        base: { sha: BASE, ref: 'main', repo: { id: 100 } },
        changed_files: files.length,
        commits: commits.length,
      },
      files,
      commits,
      comments: [],
      threads: [],
      timeline: [],
      statuses: [],
      dependabotPolicy: options.dependabotPolicy ?? null,
    },
    policy: clone,
  };
}

const reviewerUser = clone => ({ id: clone.policy.reviewer.user_id, login: clone.policy.reviewer.login, type: 'Bot' });

// `codex-review-state:v1` — the canonical inline format.
function stateMarker(clone, review = {}, options = {}) {
  const body = {
    code_review: {
      commit_sha: HEAD,
      has_any_findings: false,
      has_unresolved_findings: false,
      status: 'completed',
      ...review,
    },
    security_review: {},
  };
  clone.snapshot.comments.push({
    id: options.id ?? 900 + clone.snapshot.comments.length,
    user: reviewerUser(clone),
    created_at: at(options.updated ?? -60),
    updated_at: at(options.updated ?? -60),
    body: `<!-- codex-review-state:v1 ${JSON.stringify(body)} -->\n\n## Review summary\n`,
  });
  return clone;
}

// `codex-review-receipt:v1` — the module format.
function receiptMarker(clone, review = {}, options = {}) {
  const body = {
    review: { commit_sha: HEAD, coverage: 'complete', unresolved_findings: 0, ...review },
  };
  clone.snapshot.comments.push({
    id: options.id ?? 900 + clone.snapshot.comments.length,
    user: reviewerUser(clone),
    created_at: at(options.updated ?? -60),
    updated_at: at(options.updated ?? -60),
    body: `<!-- codex-review-receipt:v1 ${JSON.stringify(body)} -->\n\nReview finished.\n`,
  });
  return clone;
}

function rawComment(clone, body, options = {}) {
  clone.snapshot.comments.push({
    id: options.id ?? 900 + clone.snapshot.comments.length,
    user: options.user || reviewerUser(clone),
    created_at: at(options.updated ?? -60),
    updated_at: at(options.updated ?? -60),
    body,
  });
  return clone;
}

function thread(clone, options = {}) {
  clone.snapshot.threads.push({
    id: options.id || 'PRRT_thread_1',
    isResolved: options.resolved === true,
    isOutdated: options.outdated === true,
    author: { login: options.author ?? clone.policy.reviewer.login.replace(/\[bot\]$/, '') },
  });
  return clone;
}

// A timeline label event plus the label it leaves on the pull request.
function labelEvent(clone, options = {}) {
  const id = options.id ?? 5000 + clone.snapshot.timeline.length;
  const name = options.name || 'owner-approved';
  const event = options.event || 'labeled';
  const actor = options.actor || { id: clone.policy.owner.user_id, login: clone.policy.owner.login };
  clone.snapshot.timeline.push({ id, event, label: { name }, actor, created_at: at(options.at ?? -300) });
  const present = clone.snapshot.pr.labels.filter(item => item.name !== name);
  clone.snapshot.pr.labels = event === 'labeled' ? [...present, { name }] : present;
  return { id, name, actor, event };
}

// The immutable `clearing-label` record written by the record_label step.
function clearRecord(clone, record, options = {}) {
  clone.snapshot.statuses.push({
    context: 'clearing-label',
    state: 'success',
    description: options.description
      ?? `${record.name} for PR ${clone.snapshot.pr.number} at event ${record.id} on this head`,
    creator: { id: 41898282, login: 'github-actions[bot]' },
  });
  return clone;
}

function approve(clone) {
  return receiptMarker(clone);
}

module.exports = {
  policy, HEAD, BASE, POLICY_SHA, NOW, COMPLETE_TEMPLATE, at,
  fixture, stateMarker, receiptMarker, rawComment, thread, labelEvent, clearRecord, approve,
};
