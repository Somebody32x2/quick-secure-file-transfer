/**
 * What the production bundle actually contains.
 *
 * One thing here is load-bearing and invisible from the source: Vite resolves
 * `import.meta.env.BASE_URL` at build time by *pattern-matching the expression*,
 * so client/src/config.ts is written in a shape Vite recognises. Get that shape
 * wrong and nothing fails loudly - the app builds, runs at the origin root, and
 * only a subpath deployment breaks, by requesting `/api/...` instead of
 * `/filetransfer/api/...`. That is a production-only failure on a documented
 * deployment, so it is checked against a real build rather than reasoned about.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function buildInto(basePath: string): Promise<{ js: string; html: string }> {
  const outDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qsft-build-'));
  try {
    execFileSync(
      process.execPath,
      [path.join(root, 'node_modules', 'vite', 'bin', 'vite.js'),
        'build', '--logLevel', 'error', '--outDir', outDir, '--emptyOutDir'],
      { cwd: root, env: { ...process.env, BASE_PATH: basePath }, stdio: ['ignore', 'pipe', 'pipe'] },
    );

    const assets = path.join(outDir, 'assets');
    const names = await fs.readdir(assets);
    const entry = names.find((n) => n.startsWith('index-') && n.endsWith('.js'));
    assert.ok(entry, `no entry chunk in ${names.join(', ')}`);

    return {
      js: await fs.readFile(path.join(assets, entry!), 'utf8'),
      html: await fs.readFile(path.join(outDir, 'index.html'), 'utf8'),
    };
  } finally {
    await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}

test('a subpath build bakes the mount point into the bundle', async () => {
  const { js, html } = await buildInto('/filetransfer');

  // config.ts's BASE, resolved at build time - not left as a runtime lookup that
  // would evaluate to undefined and silently fall back to the origin root.
  assert.match(js, /"\/filetransfer\/"/, 'BASE_URL should be substituted into the bundle');
  assert.doesNotMatch(js, /import\.meta\.env/, 'import.meta.env must not survive into the bundle');

  // And the asset URLs the page loads follow it.
  assert.match(html, /\/filetransfer\/assets\//, 'index.html should reference subpath assets');
});

test('a root build mounts at the origin root', async () => {
  const { js, html } = await buildInto('');
  assert.doesNotMatch(js, /import\.meta\.env/);
  assert.doesNotMatch(html, /\/filetransfer\//);
  assert.match(html, /src="\/assets\//, 'root build should reference /assets/');
});
