#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Metacraft Labs / Schelling Point Labs
# SPDX-License-Identifier: Apache-2.0
"""The docs site builds only from its committed flake lock.

From 2026-10-18 the GitHub Pages build of `docs/site` failed on every run,
on `dev` and `agents`, with nothing changed in io-mon. The flake had no
committed `flake.lock`, so each run resolved every input to its branch head,
and upstream nim-stew dropped `readPragma` (status-im/nim-stew eeff9f5), which
isonim's vendored serialization and chronicles still call.

This test holds the site to what the published build needs:

1. `docs/site/flake.lock` is tracked by git, and every input `flake.nix`
   declares is locked to an exact revision with a NAR hash.
2. The Pages workflow builds with `--no-update-lock-file`, so a lock that has
   gone stale fails the build instead of being re-resolved to branch heads.
3. The Pages workflow is not triggered by pushes to `agents` (the agent
   landing branch runs no CI).
4. With `--build`, the site is really built exactly as the workflow builds
   it -- `nix develop ./docs/site --no-update-lock-file`, then
   `nim c -r src/build.nim` -- from a copy of only the git-tracked files of
   `docs/site` (so an untracked lock in the working tree cannot make it pass),
   and the build must write `public/index.html`.

Nothing is mocked: the checks read the real lock, flake and workflow, and
`--build` runs the real Nix evaluation and Nim compiler. `--build` needs Nix
and network access to fetch the locked inputs; run it outside any dev shell.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SITE = 'docs/site'
WORKFLOW = '.github/workflows/docs-pages.yml'


def fail(message):
    print(f'FAIL: {message}', file=sys.stderr)
    sys.exit(1)


def tracked(path):
    result = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '--error-unmatch', path],
                            capture_output=True, text=True)
    return result.returncode == 0


def declared_inputs(flake_text):
    """Top-level input names of `docs/site/flake.nix`.

    Matches `name.url = ...` and `name = {` at the inputs block's indentation;
    the flake is ours and keeps that shape, and `check_lock` cross-checks the
    result against the lock's root node, so a missed or extra name fails.
    """
    block = re.search(r'^  inputs = \{\n(.*?)^  \};', flake_text, re.S | re.M)
    if not block:
        fail('docs/site/flake.nix: no top-level `inputs = { ... };` block found')
    names = set(re.findall(r'^    ([A-Za-z0-9_-]+)(?:\.url\s*=|\s*=\s*\{)', block.group(1), re.M))
    if not names:
        fail('docs/site/flake.nix: the inputs block declares no inputs')
    return names


def check_lock():
    lock_path = f'{SITE}/flake.lock'
    if not tracked(lock_path):
        fail(f'{lock_path} is not tracked by git: every build resolves the docs '
             'inputs to their branch heads, so an upstream change breaks the site')
    lock = json.loads((ROOT / lock_path).read_text())
    nodes = lock['nodes']
    root_inputs = nodes[lock['root']].get('inputs', {})
    declared = declared_inputs((ROOT / SITE / 'flake.nix').read_text())
    if set(root_inputs) != declared:
        fail(f'{lock_path} root inputs {sorted(root_inputs)} differ from the inputs '
             f'flake.nix declares {sorted(declared)}: the lock is stale; run '
             '`nix flake lock ./docs/site`')
    for name, node_name in sorted(root_inputs.items()):
        if not isinstance(node_name, str):
            fail(f'{lock_path}: root input {name} is a `follows`, not a locked input')
        locked = nodes[node_name].get('locked', {})
        if not locked.get('narHash') or not re.fullmatch(r'[0-9a-f]{40}', locked.get('rev', '')):
            fail(f'{lock_path}: input {name} is not locked to a revision and NAR hash: {locked}')
    print(f'ok: {lock_path} is tracked and locks {len(root_inputs)} inputs')


def check_workflow():
    text = (ROOT / WORKFLOW).read_text()
    builds = re.findall(r'nix develop \./docs/site[^\n]*', text)
    if not builds:
        fail(f'{WORKFLOW}: no `nix develop ./docs/site` build step found')
    for line in builds:
        if '--no-update-lock-file' not in line:
            fail(f'{WORKFLOW}: `{line.strip()}` may re-resolve the docs inputs; '
                 'pass --no-update-lock-file')
    branches = re.search(r'^  push:\n    branches: \[([^\]]*)\]', text, re.M)
    if not branches:
        fail(f'{WORKFLOW}: no `on.push.branches` list found')
    if 'agents' in [b.strip() for b in branches.group(1).split(',')]:
        fail(f'{WORKFLOW}: pushes to `agents` trigger the docs workflow; the agent '
             'landing branch runs no CI')
    print(f'ok: {WORKFLOW} builds from the lock and is not triggered by `agents`')


def build_site():
    """Build the site from a copy of `docs/site`'s git-tracked files (in their
    working-tree state), exactly as the workflow does."""
    with tempfile.TemporaryDirectory(prefix='io-mon-docs-') as tmp:
        tree = Path(tmp) / 'tree'
        # Copy only tracked files (as in the working tree), so the result is
        # what a CI checkout of this commit sees. A git repo is needed for
        # `nix develop ./docs/site` to treat it as a git flake, as in CI.
        files = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', SITE],
                               capture_output=True, check=True).stdout.split(b'\0')
        for f in filter(None, files):
            src = ROOT / f.decode()
            dst = tree / f.decode()
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_symlink():
                dst.symlink_to(src.readlink())
            elif src.exists():
                shutil.copy2(src, dst)
        subprocess.run(['git', 'init', '-q', str(tree)], check=True)
        subprocess.run(['git', '-C', str(tree), 'add', '-A'], check=True)
        cmd = ['nix', 'develop', './docs/site', '--no-update-lock-file', '--command',
               'bash', '-c', 'cd docs/site && nim c -r --hints:off -o:build/build src/build.nim']
        print('+', ' '.join(cmd), flush=True)
        result = subprocess.run(cmd, cwd=tree)
        if result.returncode != 0:
            fail(f'the docs site build exited {result.returncode}')
        index = tree / SITE / 'public/index.html'
        if not index.is_file() or index.stat().st_size == 0:
            fail('the docs site build wrote no public/index.html')
        pages = len(list((tree / SITE / 'public').rglob('*.html')))
        print(f'ok: the docs site built from its lock ({pages} HTML pages)')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--build', action='store_true',
                        help='also build the site from the lock, as the Pages workflow does')
    args = parser.parse_args()
    check_lock()
    check_workflow()
    if args.build:
        build_site()


if __name__ == '__main__':
    main()
