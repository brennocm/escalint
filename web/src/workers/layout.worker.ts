import { forceLayout, type ForceInput } from '../layout/force';
import { serve, type CallContext } from './rpc';

// Runs the Atlas force layout off the main thread.
serve(self, {
  force: (input: ForceInput, ctx: CallContext) => forceLayout(input, ctx.cancelled),
});
