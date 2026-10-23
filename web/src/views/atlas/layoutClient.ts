import { forceLayout, type ForceInput, type ForceOutput } from '../../layout/force';
import { createClient, type CallContext, type Client } from '../../workers/rpc';

type Methods = { force: (input: ForceInput, ctx: CallContext) => ForceOutput } & Record<
  string,
  (input: never, ctx: CallContext) => unknown
>;

let client: Client<Methods> | null | undefined;

function getClient(): Client<Methods> | null {
  if (client !== undefined) return client;
  try {
    // Workers are unavailable in some contexts (the single-file HTML report
    // under file://, tests); the layout then runs on the main thread.
    const w = new Worker(new URL('../../workers/layout.worker.ts', import.meta.url), {
      type: 'module',
    });
    client = createClient<Methods>(w);
  } catch {
    client = null;
  }
  return client;
}

export async function runLayout(input: ForceInput, signal: AbortSignal): Promise<ForceOutput> {
  const c = getClient();
  if (c) {
    try {
      return await c.call('force', input, signal);
    } catch (err) {
      if (signal.aborted) throw err;
      client = null; // a broken worker: fall back below
    }
  }
  // Main-thread fallback with fewer iterations for large graphs.
  const n = input.ids.length;
  return forceLayout(
    n > 5000 && input.iterations === undefined ? { ...input, iterations: 60 } : input,
    () => signal.aborted,
  );
}
