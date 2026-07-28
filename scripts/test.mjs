#!/usr/bin/env node
// Node 20's test runner does not discover .ts files or expand globs on Windows,
// so collect the test files ourselves and hand them over explicitly.
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testDir = path.join(root, 'test');
const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.ts'))
  .map((name) => path.join('test', name));

if (files.length === 0) {
  console.error('No test files found in test/');
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ['--import', 'tsx', '--test', ...files],
  { cwd: root, stdio: 'inherit' },
);
process.exit(result.status ?? 1);
