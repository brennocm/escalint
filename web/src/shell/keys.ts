import type { View } from '../state/route';

export type KeyAction =
  | { readonly type: 'palette' }
  | { readonly type: 'help' }
  | { readonly type: 'theme' }
  | { readonly type: 'pseudonyms' }
  | { readonly type: 'escape' }
  | { readonly type: 'go'; readonly view: View };

const goKeys: Record<string, View> = {
  o: 'overview',
  a: 'atlas',
  f: 'findings',
  e: 'exposure',
  x: 'fix',
  d: 'diff',
};

/** Maps key presses to actions. `pending` carries a "g" prefix between
 * presses. Keys typed into inputs are ignored except Ctrl/⌘+K and Escape. */
export function keyAction(
  e: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'altKey'>,
  inField: boolean,
  pending: string,
): { action: KeyAction | null; pending: string } {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')
    return { action: { type: 'palette' }, pending: '' };
  if (e.key === 'Escape') return { action: { type: 'escape' }, pending: '' };
  if (inField || e.ctrlKey || e.metaKey || e.altKey) return { action: null, pending: '' };
  if (pending === 'g') {
    const view = goKeys[e.key];
    return { action: view ? { type: 'go', view } : null, pending: '' };
  }
  switch (e.key) {
    case '?':
      return { action: { type: 'help' }, pending: '' };
    case 't':
      return { action: { type: 'theme' }, pending: '' };
    case 'p':
      return { action: { type: 'pseudonyms' }, pending: '' };
    case 'g':
      return { action: null, pending: 'g' };
    default:
      return { action: null, pending: '' };
  }
}
