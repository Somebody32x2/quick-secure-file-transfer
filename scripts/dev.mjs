#!/usr/bin/env node
// Runs the API/signaling server and the Vite dev server together, no extra deps.
import { spawn } from 'node:child_process';

const procs = [
  spawn('node', ['server/index.js'], { stdio: 'inherit', shell: false, env: { ...process.env, NODE_ENV: 'development' } }),
  spawn(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['vite'], { stdio: 'inherit', shell: process.platform === 'win32' }),
];

let closing = false;
const shutdown = (code = 0) => {
  if (closing) return;
  closing = true;
  for (const p of procs) if (!p.killed) p.kill();
  process.exit(code);
};

for (const p of procs) p.on('exit', (c) => shutdown(c ?? 0));
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
