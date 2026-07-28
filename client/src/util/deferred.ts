export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
}

export function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  // Nothing may be awaiting this yet; swallow the unhandled-rejection warning.
  promise.catch(() => {});
  return { promise, resolve, reject };
}

export class AbortedError extends Error {
  constructor(message = 'Cancelled') {
    super(message);
    this.name = 'AbortedError';
  }
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new AbortedError();
}
