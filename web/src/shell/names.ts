import type { Node } from '../contract/analysis';
import { nodeLabel } from '../data/indexes';

/** Display names are clipped: IAM names are at most 128 characters, so a
 * longer value comes from a tampered file and must not slow the UI down. */
export const maxNameLength = 160;

export function clip(s: string, max = maxNameLength): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Name to show for a node. With pseudonyms on, principals and external
 * identities are shown as "<kind> <id suffix>", which is stable per node
 * and reveals nothing (IDs are hashes, or HMAC pseudonyms when redacted). */
export function displayName(n: Node, pseudonyms: boolean): string {
  if (
    !pseudonyms ||
    n.kind === 'tier0_sink' ||
    n.kind === 'service' ||
    n.kind === 'any_principal'
  ) {
    return clip(nodeLabel(n));
  }
  return `${n.kind.replace('_', ' ')} ${n.id.slice(2, 8)}`;
}

export function displayArn(n: Node, pseudonyms: boolean): string {
  if (pseudonyms) return n.id;
  return clip(n.arn ?? n.name, 2048);
}

export function displayAccount(account: string, pseudonyms: boolean): string {
  return pseudonyms && /^\d{12}$/.test(account) ? `acct ${account.slice(-4)}` : account;
}
