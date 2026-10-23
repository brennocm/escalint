import { afterEach, describe, expect, it } from 'vitest';
import {
  CancelledError,
  createClient,
  latest,
  serve,
  type CallContext,
  type PortLike,
} from './rpc';

interface M {
  [method: string]: (input: never, ctx: CallContext) => unknown;
  double: (n: number) => number;
  slow: (n: number, ctx: CallContext) => Promise<number>;
  fail: (s: string) => never;
}

const channels: MessageChannel[] = [];
function pair(): [PortLike, PortLike] {
  const ch = new MessageChannel();
  channels.push(ch);
  ch.port1.start();
  ch.port2.start();
  return [ch.port1, ch.port2];
}
afterEach(() => {
  for (const ch of channels.splice(0)) {
    ch.port1.close();
    ch.port2.close();
  }
});

const seen: number[] = [];
const methods = {
  double: (n: number) => n * 2,
  slow: async (n: number, ctx: CallContext) => {
    for (let i = 0; i < 20; i++) {
      if (ctx.cancelled()) {
        seen.push(-n);
        throw new Error('stopped');
      }
      await new Promise((r) => setTimeout(r, 2));
    }
    seen.push(n);
    return n;
  },
  fail: (s: string) => {
    throw new Error(`bad ${s}`);
  },
};

describe('worker rpc', () => {
  it('calls typed methods', async () => {
    const [a, b] = pair();
    serve(b, methods);
    const client = createClient<M>(a);
    await expect(client.call('double', 21)).resolves.toBe(42);
    await expect(client.call('fail', 'x')).rejects.toThrow('bad x');
    await expect(client.call('nope' as 'double', 1)).rejects.toThrow('unknown method nope');
  });
  it('cancels the previous call when the input changes', async () => {
    const [a, b] = pair();
    serve(b, methods);
    const client = createClient<M>(a);
    const run = latest((n: number, signal: AbortSignal) => client.call('slow', n, signal));
    const first = run(1);
    const second = run(2);
    await expect(first).rejects.toBeInstanceOf(CancelledError);
    await expect(second).resolves.toBe(2);
    expect(seen).toContain(-1);
    expect(seen).not.toContain(1);
  });
  it('rejects pending calls on close and pre-aborted signals', async () => {
    const [a, b] = pair();
    serve(b, methods);
    const client = createClient<M>(a);
    const ac = new AbortController();
    ac.abort();
    await expect(client.call('double', 1, ac.signal)).rejects.toBeInstanceOf(CancelledError);
    const p = client.call('slow', 3);
    client.close();
    await expect(p).rejects.toBeInstanceOf(CancelledError);
  });
});
