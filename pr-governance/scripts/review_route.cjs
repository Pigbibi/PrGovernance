'use strict';

// Subscription reviewers are Codex and Claude. Each is on only when its flag
// says so. An empty flag keeps the historical default: Codex on, Claude off.
// When neither is on, or every enabled reviewer has reported a quota failure,
// the review is the DeepSeek API. Cursor and Bugbot are not part of this route.

const ON = new Set(['1', 'true', 'yes', 'on']);
const OFF = new Set(['0', 'false', 'no', 'off']);
const AUTO = new Set(['auto']);
const MENTION = {
  codex: '@codex review',
  claude: '@claude review',
};

function flagEnabled(value, fallback) {
  if (value == null) return fallback;
  const text = String(value).trim().toLowerCase();
  if (!text) return fallback;
  if (ON.has(text)) return true;
  if (OFF.has(text)) return false;
  if (AUTO.has(text)) return 'auto';
  throw new Error(`Invalid review subscription flag: ${value}`);
}

function flagsFromEnv(env) {
  const codex = flagEnabled(env.CODEX_REVIEW_ENABLED, true);
  const claude = flagEnabled(env.CLAUDE_REVIEW_ENABLED, false);
  return {
    codexMode: codex,
    claudeMode: claude,
    codexEnabled: codex === 'auto' ? true : codex,
    claudeEnabled: claude === 'auto' ? true : claude,
  };
}

function selectReviewRoute({ codexEnabled, claudeEnabled, quotaProviders = [] }) {
  const blocked = new Set(quotaProviders);
  const providers = [];
  if (codexEnabled && !blocked.has('codex')) providers.push('codex');
  if (claudeEnabled && !blocked.has('claude')) providers.push('claude');
  if (!providers.length) {
    return { kind: 'deepseek', providers: ['deepseek'], mentions: [] };
  }
  return {
    kind: 'subscription',
    providers,
    mentions: providers.map(name => MENTION[name]),
  };
}

module.exports = { flagEnabled, flagsFromEnv, selectReviewRoute };
