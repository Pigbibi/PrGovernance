#!/usr/bin/env python3
"""Redacted baseline, pull request range and artifact-path scans for Gitleaks 8.30.1."""
from __future__ import annotations

import argparse
from collections import Counter
import glob
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

IDENTITY_FIELDS = ('RuleID', 'File', 'Commit', 'StartLine', 'Fingerprint')
BASELINE_FIELDS = set(IDENTITY_FIELDS) | {'Secret', 'Match'}
# The scanner, its rules and its pinned binary live in the governance action, so
# the repository under judgement cannot change the rules that judge it.
ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / '.gitleaks.toml'
COMMIT = re.compile(r'[0-9a-f]{40}')


def identity(finding):
    return tuple(finding[field] for field in IDENTITY_FIELDS)


def project(finding):
    return {**{field: finding[field] for field in IDENTITY_FIELDS},
            'Secret': 'REDACTED', 'Match': 'REDACTED'}


def load_baseline(path):
    baseline = json.loads(path.read_text())
    if not isinstance(baseline, list):
        raise ValueError('Invalid baseline list')
    for finding in baseline:
        if set(finding) != BASELINE_FIELDS or any(
            finding[field] != 'REDACTED' for field in ('Secret', 'Match')
        ):
            raise ValueError('Baseline must contain only redacted identity fields')
        if not COMMIT.fullmatch(finding['Commit']):
            raise ValueError('Baseline must identify an immutable commit')
        if not isinstance(finding['StartLine'], int) or finding['StartLine'] < 1:
            raise ValueError('Invalid baseline line')
        fingerprint = f"{finding['Commit']}:{finding['File']}:{finding['RuleID']}:{finding['StartLine']}"
        if finding['Fingerprint'] != fingerprint:
            raise ValueError('Baseline fingerprint does not match its identity')
    return baseline


def reject_source_ignores(target):
    # Gitleaks also discovers ignore files in the scan source, independently of
    # --gitleaks-ignore-path. Never let unreviewed source fingerprints hide findings.
    target = Path(target)
    if target.name == '.gitleaksignore':
        raise RuntimeError('Source ignore files are not permitted')

    if target.is_file():
        if os.path.lexists(target.parent / '.gitleaksignore'):
            raise RuntimeError('Source ignore files are not permitted')
        return

    def fail_walk(error):
        raise error

    for _, directories, files in os.walk(target, onerror=fail_walk):
        if '.gitleaksignore' in directories or '.gitleaksignore' in files:
            raise RuntimeError('Source ignore files are not permitted')


def git(target, *arguments):
    try:
        return subprocess.run(['git', '-C', str(target), *arguments],
                              capture_output=True, text=True, check=False)
    except OSError:
        raise RuntimeError('Git history is unreadable; scan blocked') from None


def verify_history(target):
    # Gitleaks can report success after its internal Git reader fails. Read the
    # complete patch history first, suppressing every source-controlled diagnostic.
    try:
        root = git(target, 'rev-parse', '--show-toplevel')
        if root.returncode or Path(root.stdout.strip()).resolve() != Path(target).resolve():
            raise RuntimeError('Git history is unreadable; scan blocked')
    except (OSError, ValueError):
        raise RuntimeError('Git history is unreadable; scan blocked') from None
    for arguments in (('rev-parse', '--verify', 'HEAD^{commit}'),
                      ('log', '--all', '--full-history', '--diff-merges=first-parent', '-p', '--')):
        if git(target, *arguments).returncode:
            raise RuntimeError('Git history is unreadable; scan blocked')


def verify_range(target, base, head):
    if not COMMIT.fullmatch(base or '') or not COMMIT.fullmatch(head or ''):
        raise RuntimeError('Git range is incomplete; scan blocked')
    verify_history(target)
    for revision in (base, head):
        if git(target, 'rev-parse', '--verify', '--end-of-options',
               f'{revision}^{{commit}}').returncode:
            raise RuntimeError('Git range is unreadable; scan blocked')
    if git(target, 'log', '--full-history', '-p', '--end-of-options',
           f'{base}..{head}', '--').returncode:
        raise RuntimeError('Git range is unreadable; scan blocked')


def scan(binary, mode, target, report, baseline=None, config=None, log_opts=None):
    if mode == 'git':
        verify_history(target)
    reject_source_ignores(target)
    command = [binary, mode, str(target), '--config', str(config or CONFIG),
               '--ignore-gitleaks-allow', '--redact', '--no-banner',
               '--report-format', 'json', '--report-path', str(report)]
    if mode == 'git':
        # Plain `git log -p` hides merge diffs, so a credential added only while
        # resolving a conflict would never appear in the history scan.
        command.append('--log-opts=' + (log_opts or '--all --diff-merges=first-parent'))
    if baseline is not None:
        command.extend(['--baseline-path', str(baseline)])
    result = subprocess.run(command, capture_output=True, check=False)
    if result.returncode not in (0, 1) or not report.is_file():
        raise RuntimeError('Gitleaks failed; no artifact may be uploaded')
    findings = json.loads(report.read_text())
    if not isinstance(findings, list) or bool(findings) != bool(result.returncode):
        raise RuntimeError('Gitleaks returned an inconsistent result')
    return findings


def write_summary(path, findings):
    # Only aggregate counts may leave the run: a path or commit prefix in the
    # artifact is enough to recover the value from history.
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(finding['RuleID'] for finding in findings)
    path.write_text(json.dumps({'new_findings': len(findings),
                                'by_rule': dict(sorted(counts.items()))}, indent=2) + '\n')


def history(binary, baseline_path, summary, create=False, root=None, config=None):
    root = Path(root or ROOT).resolve()
    with tempfile.TemporaryDirectory(prefix='gitleaks-', dir=os.environ.get('RUNNER_TEMP')) as directory:
        findings = scan(binary, 'git', root, Path(directory) / 'history.json', config=config)
        if create:
            if baseline_path.exists():
                raise ValueError('Refusing to replace an existing history baseline')
            baseline_path.write_text(json.dumps([project(finding) for finding in findings], indent=2) + '\n')
        known = Counter(identity(finding) for finding in load_baseline(baseline_path))
        remaining = known.copy()
        new_findings = []
        for finding in findings:
            key = identity(finding)
            if remaining[key] > 0:
                remaining[key] -= 1
            else:
                new_findings.append(finding)
        write_summary(summary, new_findings)
        print(f'History scan: {len(new_findings)} new finding(s); {len(known)} baseline identities')
        return int(bool(new_findings))


def range_scan(binary, base, head, root=None, config=None):
    root = Path(root or ROOT).resolve()
    verify_range(root, base, head)
    with tempfile.TemporaryDirectory(prefix='gitleaks-', dir=os.environ.get('RUNNER_TEMP')) as directory:
        findings = scan(binary, 'git', root, Path(directory) / 'range.json',
                        config=config, log_opts=f'{base}..{head}')
    if findings:
        print(f'Range scan: {len(findings)} finding(s) in added commits')
    else:
        print('Range scan passed: no finding in added commits')
    return int(bool(findings))


def artifacts(binary, patterns, config=None):
    paths = sorted({Path(match) for pattern in patterns.splitlines() if pattern.strip()
                    for match in glob.glob(pattern.strip(), recursive=True)})
    with tempfile.TemporaryDirectory(prefix='gitleaks-', dir=os.environ.get('RUNNER_TEMP')) as directory:
        for index, path in enumerate(paths):
            findings = scan(binary, 'dir', path, Path(directory) / f'{index}.json', config=config)
            if findings:
                print('Artifact scan blocked upload: credential finding(s); values suppressed')
                for finding in findings:
                    print(json.dumps({'File': finding['File'], 'RuleID': finding['RuleID']}))
                return 1
    print(f'Artifact scan passed: {len(paths)} matching upload path(s)')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('history', 'range', 'artifacts'))
    parser.add_argument('--gitleaks', default='gitleaks')
    parser.add_argument('--root', type=Path, help='repository under judgement')
    parser.add_argument('--config', type=Path, help='rules shipped with the governance action')
    parser.add_argument('--base')
    parser.add_argument('--head')
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--summary', type=Path)
    parser.add_argument('--create-baseline', action='store_true')
    arguments = parser.parse_args()
    try:
        if arguments.mode == 'artifacts':
            return artifacts(arguments.gitleaks, os.environ['ARTIFACT_PATHS'], arguments.config)
        if arguments.mode == 'range':
            if not arguments.base or not arguments.head:
                parser.error('range requires --base and --head')
            return range_scan(arguments.gitleaks, arguments.base, arguments.head,
                              arguments.root, arguments.config)
        if arguments.summary is None:
            parser.error('history requires --summary')
        if arguments.baseline is None:
            parser.error('history requires --baseline')
        return history(arguments.gitleaks, arguments.baseline, arguments.summary,
                       arguments.create_baseline, arguments.root, arguments.config)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        print('Secret scan failed safely; values and raw reports suppressed')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
