/** HTTP client for the store-and-forward path and server configuration. */

import { api } from '../config.js';
import type { IceServerConfig } from './p2p.js';

export interface ServerConfig {
  maxFileBytes: number;
  maxPartBytes: number;
  maxTtlSeconds: number;
  defaultTtlSeconds: number;
  maxReadsLimit: number;
  iceServers: IceServerConfig[];
}

export interface UploadTicket {
  id: string;
  code: string;
  token: string;
  expiresAt: number;
  maxReads: number;
  maxPartBytes: number;
}

export interface StoredMeta {
  size: number;
  expiresAt: number;
  readsRemaining: number;
  maxReads: number;
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'ApiError';
  }
}

async function parseError(response: Response): Promise<never> {
  let message = `Request failed (${response.status})`;
  try {
    const body = await response.json();
    if (body?.error) message = body.error;
  } catch { /* non-JSON error body */ }
  throw new ApiError(message, response.status);
}

let cachedConfig: ServerConfig | null = null;

export async function fetchServerConfig(): Promise<ServerConfig> {
  if (cachedConfig) return cachedConfig;
  const response = await fetch(api('config'));
  if (!response.ok) await parseError(response);
  cachedConfig = await response.json();
  return cachedConfig!;
}

export async function initUpload(params: {
  ttlSeconds: number;
  maxReads: number;
  declaredSize: number;
}): Promise<UploadTicket> {
  const response = await fetch(api('store/init'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!response.ok) await parseError(response);
  return response.json();
}

/**
 * Upload one part. Parts go up one at a time and strictly in order, which keeps
 * peak memory at a single part regardless of file size and lets a dropped
 * request be retried without re-sending the whole file.
 */
export async function uploadPart(
  ticket: UploadTicket,
  index: number,
  body: Uint8Array,
  signal?: AbortSignal,
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetch(api(`store/${ticket.id}/part`), {
        method: 'PUT',
        headers: {
          'content-type': 'application/octet-stream',
          'x-upload-token': ticket.token,
          'x-part-index': String(index),
        },
        body: body as unknown as BodyInit,
        signal,
      });
      if (response.ok) return;
      // The server rejects a genuinely bad request the same way every time;
      // only transient failures are worth another go.
      if (response.status < 500) await parseError(response);
      lastError = new ApiError(`Server error (${response.status})`, response.status);
    } catch (err) {
      if (signal?.aborted) throw err;
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
  }
  throw lastError instanceof Error ? lastError : new Error('Upload failed');
}

export async function commitUpload(ticket: UploadTicket): Promise<{
  code: string; expiresAt: number; maxReads: number; size: number;
}> {
  const response = await fetch(api(`store/${ticket.id}/commit`), {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-upload-token': ticket.token },
    body: '{}',
  });
  if (!response.ok) await parseError(response);
  return response.json();
}

export async function revokeUpload(ticket: UploadTicket): Promise<void> {
  await fetch(api(`store/${ticket.id}/revoke`), {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-upload-token': ticket.token },
    body: '{}',
  }).catch(() => { /* best effort */ });
}

export type ResolvedCode =
  | ({ kind: 'stored' } & StoredMeta)
  | { kind: 'live' };

/** One lookup tells the receiver whether a code is a waiting sender or a stored blob. */
export async function resolveCode(code: string): Promise<ResolvedCode> {
  const response = await fetch(api(`resolve/${encodeURIComponent(code)}`));
  if (!response.ok) await parseError(response);
  return response.json();
}


/** Streamed download. Response streaming works in every current browser. */
export async function openStoredDownload(
  code: string,
  signal?: AbortSignal,
): Promise<{ stream: ReadableStream<Uint8Array>; size: number }> {
  const response = await fetch(api(`store/${encodeURIComponent(code)}`), { signal });
  if (!response.ok) await parseError(response);
  if (!response.body) throw new ApiError('This browser cannot stream the download', 500);
  return {
    stream: response.body as ReadableStream<Uint8Array>,
    size: Number(response.headers.get('content-length')) || 0,
  };
}
