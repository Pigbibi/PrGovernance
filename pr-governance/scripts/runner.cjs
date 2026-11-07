'use strict';

const gate = require('./gate.cjs');

// GitHub reports the status author without the bot suffix used in comment
// payloads, so every identity comparison normalises it.
const PUBLISHER = { id: 41898282, login: 'github-actions[bot]' };
const STATUS_LIMIT = 1000;
const CONTEXTS = ['pr-template', 'ai-review', 'risk-gate'];
const POLICY_PATH = '.github/governance/policy.json';
const DEPENDABOT_POLICY_PATH = '.github/scripts/dependabot-policy.json';

const found = (message, code) => Object.assign(new Error(message), { code });

async function selectTargets(github, context, defaultBranch) {
  const repo = context.repo;
  const event = context.payload || {};
  const openPullRequests = () => github.paginate(github.rest.pulls.list,
    { ...repo, state: 'open', base: defaultBranch, per_page: 100 });
  if (context.eventName === 'push' || context.eventName === 'schedule') {
    return (await openPullRequests()).map(pull => pull.number);
  }
  if (context.eventName === 'pull_request_target' || context.eventName === 'pull_request') {
    const pull = event.pull_request;
    if (!pull) throw new Error('Missing pull request payload');
    // Closing a pull request can end a shared-head collision, so the remaining
    // open pull requests are re-evaluated instead of the one that just closed.
    if (event.action === 'closed') {
      return (await openPullRequests()).filter(item => item.number !== pull.number).map(item => item.number);
    }
    if (!Number.isSafeInteger(pull.number) || pull.number < 1) throw new Error('Invalid PR number');
    return [pull.number];
  }
  if (context.eventName === 'issue_comment') {
    if (!event.issue?.pull_request) return [];
    if (!Number.isSafeInteger(event.issue.number) || event.issue.number < 1) throw new Error('Invalid PR number');
    return [event.issue.number];
  }
  if (context.eventName === 'workflow_dispatch') {
    if (context.ref !== `refs/heads/${defaultBranch}`) throw new Error('Dispatch must use the default branch');
    const number = Number(event.inputs?.pr_number);
    if (!Number.isSafeInteger(number) || number < 1) throw new Error('Invalid PR number');
    return [number];
  }
  throw found('Unsupported event', 'UNSUPPORTED_EVENT');
}

async function readThreads(github, repo, number) {
  const threads = [];
  let cursor = null;
  do {
    // The author of a thread decides whether it blocks, so the first comment is
    // part of the query rather than a second round trip per thread.
    const data = await github.graphql(`query($owner:String!,$repo:String!,$number:Int!,$cursor:String) {
      repository(owner:$owner,name:$repo) { pullRequest(number:$number) {
        reviewThreads(first:100,after:$cursor) {
          nodes { id isResolved isOutdated comments(first:1) { nodes { author { login databaseId } } } }
          pageInfo { hasNextPage endCursor }
        }
      } }
    }`, { ...repo, number, cursor });
    const page = data?.repository?.pullRequest?.reviewThreads;
    if (!page || !Array.isArray(page.nodes) || !page.pageInfo) throw new Error('Incomplete review threads');
    for (const node of page.nodes) {
      if (!node?.id || typeof node.isResolved !== 'boolean') throw new Error('Invalid review thread');
      threads.push({ id: node.id, isResolved: node.isResolved, isOutdated: node.isOutdated === true,
        author: { login: node.comments?.nodes?.[0]?.author?.login ?? null,
          id: node.comments?.nodes?.[0]?.author?.databaseId ?? null } });
    }
    const next = page.pageInfo.hasNextPage ? page.pageInfo.endCursor : null;
    if (page.pageInfo.hasNextPage && (!next || next === cursor)) throw new Error('Invalid thread page');
    cursor = next;
  } while (cursor);
  return threads;
}

async function readDependabotPolicy(github, repo, ref) {
  try {
    const { data } = await github.rest.repos.getContent({ ...repo, path: DEPENDABOT_POLICY_PATH, ref });
    if (data?.type !== 'file' || typeof data.content !== 'string') return null;
    const parsed = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8'));
    if (!parsed || !Array.isArray(parsed.action_files)) return null;
    return { action_files: parsed.action_files.filter(path => typeof path === 'string').sort() };
  } catch {
    // A missing or unreadable dependency policy grants no exemption.
    return null;
  }
}

async function collect(github, context, number, policyCommit) {
  const repo = context.repo;
  const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: number });
  const params = { ...repo, pull_number: number, per_page: 100 };
  const [files, commits, comments, timeline, statuses, threads, dependabotPolicy] = await Promise.all([
    github.paginate(github.rest.pulls.listFiles, params),
    github.paginate(github.rest.pulls.listCommits, params),
    github.paginate(github.rest.issues.listComments, { ...repo, issue_number: number, per_page: 100 }),
    github.paginate(github.rest.issues.listEvents, { ...repo, issue_number: number, per_page: 100 }),
    github.paginate(github.rest.repos.listCommitStatusesForRef, { ...repo, ref: pr.head.sha, per_page: 100 }),
    readThreads(github, repo, number),
    readDependabotPolicy(github, repo, policyCommit),
  ]);
  return {
    repository: `${repo.owner}/${repo.repo}`,
    policyCommit,
    pr,
    files,
    commits,
    comments,
    timeline,
    statuses,
    threads,
    dependabotPolicy,
    complete: true,
  };
}

function snapshotVersion(snapshot) {
  // Only security-relevant fields: mergeability, reactions and other churn must
  // not invalidate an evaluation, while comment edits still do through the
  // timestamp (bodies are never part of a digest).
  const pr = snapshot.pr;
  return gate.digest({
    repository: snapshot.repository,
    policy_commit: snapshot.policyCommit,
    pr: {
      state: pr.state,
      number: pr.number,
      body: pr.body,
      head: pr.head?.sha,
      base: pr.base?.sha,
      base_ref: pr.base?.ref,
      base_repo: pr.base?.repo?.id ?? null,
      labels: (pr.labels || []).map(label => label.name).sort(),
      author: { id: pr.user?.id ?? null, login: pr.user?.login ?? null },
      changed_files: pr.changed_files,
      commits: pr.commits,
    },
    files: snapshot.files,
    commits: (snapshot.commits || []).map(commit => ({
      author: commit.author?.login ?? null,
      committer: commit.committer?.login ?? null,
      verified: commit.commit?.verification?.verified === true,
    })),
    comments: (snapshot.comments || []).map(gate.stableComment),
    threads: (snapshot.threads || []).map(gate.stableThread),
    timeline: (snapshot.timeline || []).map(event => ({ id: event.id, event: event.event,
      label: event.label?.name ?? null, actor: event.actor?.id ?? null })),
    clearing: (snapshot.statuses || []).filter(status => status.context === 'clearing-label')
      .map(status => ({ context: status.context, state: status.state, description: status.description }))
      .sort((left, right) => (left.description < right.description ? -1 : 1)),
    dependabot_policy: snapshot.dependabotPolicy,
  });
}

// The `labeled` payload is the only authenticated record of which head a
// clearing label was added to, and the payload carries no event id. Matching the
// addition's own timestamp against the timeline names that exact addition, so a
// revoked and re-added label cannot reuse an earlier record.
async function recordLabel({ github, context, core }) {
  if (context.eventName !== 'pull_request_target' || context.payload?.action !== 'labeled') return null;
  const label = context.payload.label?.name;
  if (!gate.CLEARING_LABELS.includes(label)) return null;
  const pull = context.payload.pull_request;
  if (!pull || pull.state !== 'open' || !pull.head?.sha || !Number.isSafeInteger(pull.number)) return null;
  const addedAt = pull.updated_at;
  if (!addedAt) return null;
  const events = await github.paginate(github.rest.issues.listEvents,
    { ...context.repo, issue_number: pull.number, per_page: 100 });
  const matches = events.filter(event => event.event === 'labeled' && event.label?.name === label
    && event.created_at === addedAt && Number.isSafeInteger(event.actor?.id));
  // Two additions in the same second cannot be told apart; recording either
  // could credit the wrong head, so this delivery records nothing.
  if (matches.length !== 1) return null;
  const event = matches[0];
  const description = `${label} for PR ${pull.number} at event ${event.id} on this head`;
  const target = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
  await github.rest.repos.createCommitStatus({ ...context.repo, sha: pull.head.sha,
    context: 'clearing-label', state: 'success', description, target_url: target });
  core?.info?.(`Recorded ${label} (event ${event.id}, actor ${event.actor.id}) for PR #${pull.number}`);
  return { label, event_id: event.id, actor_id: event.actor.id, actor_login: event.actor.login ?? null, sha: pull.head.sha };
}

const collisionEntries = () => CONTEXTS.map(context => ({
  context, state: 'error', description: 'Another open pull request shares this head',
}));

const errorEntries = description => CONTEXTS.map(context => ({ context, state: 'error', description }));

// Writes the entries that are not already current, and refuses to spend the last
// status slot of a context on anything but a blocking state.
async function publishAll({ github, repo, head, history, entries, mode, target }) {
  // `local` mode is a dry run: the verdict is reported, nothing is claimed.
  if (mode === 'local') return [];
  const planned = [];
  let exhausted = false;
  for (const entry of entries) {
    const own = history.filter(status => status.context?.toLowerCase() === entry.context);
    const description = (mode === 'report-only' ? `report-only: ${entry.description}` : entry.description).slice(0, 140);
    const latest = own[0];
    if (latest?.creator?.id === PUBLISHER.id && latest.creator.login === PUBLISHER.login
      && latest.state === entry.state && latest.description === description) continue;
    // GitHub allows 1000 statuses per commit and context. Keep the last slot for
    // a blocking state instead of spending it on a claim.
    if (own.length >= STATUS_LIMIT) { exhausted = true; continue; }
    if (own.length >= STATUS_LIMIT - 1) {
      planned.push({ context: entry.context, state: 'error', description: 'Commit status limit reached; new head required' });
      exhausted = true;
      continue;
    }
    planned.push({ context: entry.context, state: entry.state, description });
  }
  const written = [];
  for (const entry of planned) {
    const { data } = await github.rest.repos.createCommitStatus({ ...repo, sha: head,
      context: entry.context, state: entry.state, description: entry.description, target_url: target });
    history.unshift(data);
    written.push(data);
  }
  if (exhausted) throw found('Commit status limit reached; no verdict may be published', 'STATUS_LIMIT');
  return written;
}

async function publishUnavailable({ github, context, core, number, mode }) {
  const { data: pull } = await github.rest.pulls.get({ ...context.repo, pull_number: number });
  if (pull.state !== 'open' || !gate.isSha(pull.head.sha)) return;
  const history = await github.paginate(github.rest.repos.listCommitStatusesForRef,
    { ...context.repo, ref: pull.head.sha, per_page: 100 });
  const target = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
  try {
    await publishAll({ github, repo: context.repo, head: pull.head.sha, history,
      entries: errorEntries('Governance policy unavailable; rerun required'), mode, target });
  } catch (error) {
    core?.warning?.(`PR #${number}: ${error.message}`);
  }
}

async function evaluateOne(options) {
  const { github, context, core, policy, policySha, policyCommit, defaultBranch, now, number, mode } = options;
  const repo = context.repo;
  const target = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${context.runId}`;
  const { data: initial } = await github.rest.pulls.get({ ...repo, pull_number: number });
  if (initial.state !== 'open') return { number, skipped: true };
  const head = initial.head.sha;
  let history = [];

  const publish = entries => publishAll({ github, repo, head, history, entries, mode, target });

  const sharedHead = async () => {
    const open = await github.paginate(github.rest.pulls.list, { ...repo, state: 'open', per_page: 100 });
    return open.some(item => item.number !== number && item.head?.sha === head);
  };

  try {
    // An unreadable head leaves no place to publish; a non-default base is
    // governed by its own branch policy, so both fail closed with error
    // statuses rather than claiming anything.
    if (!gate.isSha(head)) throw new Error('Unknown head commit');
    if (initial.base.ref !== defaultBranch) throw new Error('Only the default branch is governed');
    if (await sharedHead()) {
      const before = await collect(github, context, number, policyCommit);
      history = before.statuses;
      await publish(collisionEntries());
      throw found('Another open pull request shares this head; statuses would collide', 'SHARED_HEAD');
    }
    const before = await collect(github, context, number, policyCommit);
    history = before.statuses;
    if (before.pr.head.sha !== head) throw new Error('Head changed during collection');
    const dependabot = gate.dependabotEvidence(before, policy);
    if (before.pr.base.sha !== policyCommit) {
      // A stale base is a stable state, not a failed read: the evidence binds to
      // the base it was compared against, so publish an explicit verdict instead
      // of an opaque error until the branch is rebased.
      const { tier } = gate.classify(before.files, before.pr.changed_files, policy, { dependabot });
      const template = gate.templateVerdict(before, policy, dependabot);
      await publish([
        { context: 'pr-template', state: template.state, description: template.description },
        { context: 'ai-review', state: 'failure', description: 'base-outdated: rebase to re-evaluate' },
        { context: 'risk-gate', state: 'failure', description: `${tier}: base-outdated` },
      ]);
      // A stale base blocks that pull request through its own statuses; it must
      // not fail the sweep, or every base push would go red while reviewed pull
      // requests wait to rebase.
      core?.warning?.(`PR #${number}: base ${before.pr.base.sha.slice(0, 7)} is behind ${policyCommit.slice(0, 7)}; rebase to evaluate`);
      return { number, baseOutdated: true, allowed: false, reason: 'base-outdated', tier,
        summary: { pr: number, tier, allowed: false, reason: 'base-outdated',
          base_sha: before.pr.base.sha, policy_commit: policyCommit } };
    }
    const result = gate.evaluate(before, policy, policySha, now);
    const after = await collect(github, context, number, policyCommit);
    if (after.pr.head.sha !== head) throw new Error('Head changed during evaluation');
    history = after.statuses;
    const { data: branch } = await github.rest.repos.getBranch({ ...repo, branch: defaultBranch });
    if (branch.commit?.sha !== policyCommit) throw new Error('Trusted base changed during evaluation');
    if (after.pr.base.sha !== policyCommit) throw new Error('Pull request base changed during evaluation');
    if (snapshotVersion(before) !== snapshotVersion(after)) throw new Error('Evidence changed during evaluation');
    if (await sharedHead()) {
      await publish(collisionEntries());
      throw found('Another open pull request shares this head; statuses would collide', 'SHARED_HEAD');
    }
    // Expiry can cross during the readback; never publish a stale decision.
    const final = gate.evaluate(after, policy, policySha, now);
    if (gate.digest(final) !== gate.digest(result)) throw new Error('Decision changed during evaluation');
    await publish(final.statuses);
    return { number, allowed: final.allowed, reason: final.reason, tier: final.tier, summary: final };
  } catch (error) {
    // A limit breach already wrote its blocking state; retrying would only
    // produce the same refusal.
    if (error?.code !== 'STATUS_LIMIT') {
      await Promise.allSettled([publish(errorEntries(error?.code === 'SHARED_HEAD'
        ? 'Another open pull request shares this head'
        : 'Evaluation failed; rerun required'))]);
    }
    throw error;
  }
}

function writeSummary(core, entries) {
  const summary = core?.summary;
  if (!summary || !entries.length) return;
  summary.addHeading('PR governance verdicts');
  for (const entry of entries) {
    summary.addCodeBlock(JSON.stringify(entry.summary, null, 2), 'json');
  }
  summary.addRaw('\nRequired checks and branch protection remain the merge constraint. '
    + 'This record only verifies reviewer evidence and label binding.\n');
  summary.write?.();
}

async function run({ github, context, core, policy, policySha, policyCommit, defaultBranch, now }) {
  const stamp = Number.isFinite(now) ? now : Math.floor(Date.now() / 1000);
  const mode = gate.MODES.includes(policy?.mode) ? policy.mode : 'enforce';
  const targets = await selectTargets(github, context, defaultBranch);
  const outcomes = [];
  const failures = [];
  for (const number of targets) {
    if (!policy) {
      // Policy is read from the trusted base; without it nothing can be claimed.
      failures.push({ number, message: 'policy unavailable' });
      await publishUnavailable({ github, context, core, number, mode });
      continue;
    }
    try {
      const outcome = await evaluateOne({ github, context, core, policy, policySha, policyCommit,
        defaultBranch, now: stamp, number, mode });
      if (outcome?.skipped) continue;
      outcomes.push(outcome);
      if (outcome.baseOutdated) continue;
      if (!outcome.allowed) failures.push({ number, message: outcome.reason });
    } catch (error) {
      // Do not print response bodies: they can contain user input.
      failures.push({ number, message: error?.code || error?.name || 'Error' });
    }
  }
  writeSummary(core, outcomes);
  if (!failures.length) return { evaluated: targets.length, failures };
  if (mode === 'report-only') {
    core?.warning?.(`${failures.length} pull request(s) would fail governance: ${failures.map(item => `#${item.number}`).join(', ')}`);
    return { evaluated: targets.length, failures };
  }
  if (mode === 'local') {
    core?.info?.(`${failures.length} pull request(s) would fail governance: ${failures.map(item => `#${item.number}`).join(', ')}`);
    return { evaluated: targets.length, failures };
  }
  // One failure at the end of the sweep, never one per pull request.
  core?.setFailed?.(`${failures.length} pull request(s) failed governance: ${failures.map(item => `#${item.number}`).join(', ')}`);
  return { evaluated: targets.length, failures };
}

module.exports = {
  PUBLISHER, STATUS_LIMIT, CONTEXTS, POLICY_PATH, DEPENDABOT_POLICY_PATH,
  selectTargets, readThreads, readDependabotPolicy, collect, snapshotVersion, recordLabel, run,
};
