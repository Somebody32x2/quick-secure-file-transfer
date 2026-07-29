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

/**
 * Fail a wait rather than hanging on it forever.
 *
 * A live transfer has several points where each device is waiting on the other.
 * If one of them goes wrong the honest outcome is an error that says what was
 * being waited for - not two screens sitting on "waiting" indefinitely with no
 * way to tell which side is stuck.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}
