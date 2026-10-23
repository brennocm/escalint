// Typed request/response over a Worker (or any MessagePort). Heavy layouts
// run in workers; the main thread only sends inputs and receives results.
// When an input changes, the previous request is cancelled: the worker is
// told to stop and its late answer is ignored.

/** Method table shared by client and worker: input → output. */
export type Methods = Record<string, (input: never, ctx: CallContext) => unknown>;

export interface CallContext {
  /** True once the caller cancelled; long loops should check it. */
  readonly cancelled: () => boolean;
}

export interface PortLike {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (ev: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (ev: MessageEvent) => void): void;
}

type Request =
  | { readonly id: number; readonly method: string; readonly input: unknown }
  | { readonly id: number; readonly cancel: true };
type Response =
  | { readonly id: number; readonly ok: true; readonly value: unknown }
  | { readonly id: number; readonly ok: false; readonly error: string };

export class CancelledError extends Error {
  override readonly name = 'CancelledError';
  constructor() {
    super('cancelled');
  }
}

export interface Client<M extends Methods> {
  call<K extends keyof M & string>(
    method: K,
    input: Parameters<M[K]>[0],
    signal?: AbortSignal,
  ): Promise<Awaited<ReturnType<M[K]>>>;
  close(): void;
}

export function createClient<M extends Methods>(port: PortLike): Client<M> {
  let next = 1;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  const onMessage = (ev: MessageEvent): void => {
    const res = ev.data as Response;
    const p = pending.get(res.id);
    if (!p) return; // cancelled or unknown: drop late answers
    pending.delete(res.id);
    if (res.ok) {
      p.resolve(res.value);
    } else {
      p.reject(new Error(res.error));
    }
  };
  port.addEventListener('message', onMessage);
  return {
    call(method, input, signal) {
      const id = next++;
      return new Promise((resolve, reject) => {
        if (signal?.aborted) {
          reject(new CancelledError());
          return;
        }
        pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
        signal?.addEventListener(
          'abort',
          () => {
            if (pending.delete(id)) {
              port.postMessage({ id, cancel: true } satisfies Request);
              reject(new CancelledError());
            }
          },
          { once: true },
        );
        port.postMessage({ id, method, input } satisfies Request);
      });
    },
    close() {
      port.removeEventListener('message', onMessage);
      for (const p of pending.values()) p.reject(new CancelledError());
      pending.clear();
    },
  };
}

/** Worker side: answers requests with the method table. */
export function serve(port: PortLike, methods: Methods): () => void {
  const cancelled = new Set<number>();
  const onMessage = (ev: MessageEvent): void => {
    const req = ev.data as Request;
    if ('cancel' in req) {
      cancelled.add(req.id);
      return;
    }
    const fn = methods[req.method];
    const reply = (res: Response): void => {
      if (!cancelled.delete(req.id)) port.postMessage(res);
    };
    if (!fn) {
      reply({ id: req.id, ok: false, error: `unknown method ${req.method}` });
      return;
    }
    Promise.resolve()
      .then(() => fn(req.input as never, { cancelled: () => cancelled.has(req.id) }))
      .then(
        (value) => {
          reply({ id: req.id, ok: true, value });
        },
        (err: unknown) => {
          reply({ id: req.id, ok: false, error: err instanceof Error ? err.message : String(err) });
        },
      );
  };
  port.addEventListener('message', onMessage);
  return () => {
    port.removeEventListener('message', onMessage);
  };
}

/** Runs only the latest of successive calls: starting a new one cancels
 * the previous. */
export function latest<I, O>(
  run: (input: I, signal: AbortSignal) => Promise<O>,
): (input: I) => Promise<O> {
  let controller: AbortController | null = null;
  return (input: I) => {
    controller?.abort();
    controller = new AbortController();
    return run(input, controller.signal);
  };
}
