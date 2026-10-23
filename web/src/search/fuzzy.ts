// Fuzzy search for the command palette. Ranking classes, best first:
// prefix of the text (3), start of a word (2), subsequence (1). Ties are
// broken by tier (Tier 0 first), then shorter text, then text order.

export interface Candidate {
  readonly key: string; // unique: entity ID or rule ID
  readonly kind: 'node' | 'rule' | 'path' | 'finding' | 'view';
  readonly text: string; // what is matched
  readonly label: string; // what is shown
  readonly detail: string;
  readonly tier: number; // 0..3; 4 for non-nodes
}

export interface Match {
  readonly candidate: Candidate;
  readonly score: number;
  /** Indices of matched characters in text, for highlighting. */
  readonly positions: readonly number[];
}

const separators = new Set(['/', ':', '-', '_', '.', ' ', '@', '+', '=', ',']);

function isWordStart(text: string, i: number): boolean {
  if (i === 0) return true;
  const prev = text[i - 1] ?? '';
  const cur = text[i] ?? '';
  if (separators.has(prev)) return true;
  // camelCase boundary: aB
  return prev.toLowerCase() === prev && cur.toUpperCase() === cur && cur.toLowerCase() !== cur;
}

/** Scores one text; 0 means no match. */
export function score(query: string, text: string): { score: number; positions: number[] } {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (q === '') return { score: 0, positions: [] };
  const range = (start: number): number[] => Array.from({ length: q.length }, (_, k) => start + k);
  if (t.startsWith(q)) return { score: 3, positions: range(0) };
  for (let i = t.indexOf(q); i >= 0; i = t.indexOf(q, i + 1)) {
    if (isWordStart(text, i)) return { score: 2, positions: range(i) };
  }
  const positions: number[] = [];
  let j = 0;
  for (let i = 0; i < t.length && j < q.length; i++) {
    if (t[i] === q[j]) {
      positions.push(i);
      j++;
    }
  }
  return j === q.length ? { score: 1, positions } : { score: 0, positions: [] };
}

export function search(query: string, candidates: readonly Candidate[], limit = 20): Match[] {
  const trimmed = query.trim();
  if (!trimmed) return [];
  const out: Match[] = [];
  for (const c of candidates) {
    const s = score(trimmed, c.text);
    if (s.score > 0) out.push({ candidate: c, score: s.score, positions: s.positions });
  }
  out.sort(
    (a, b) =>
      b.score - a.score ||
      a.candidate.tier - b.candidate.tier ||
      a.candidate.text.length - b.candidate.text.length ||
      (a.candidate.text < b.candidate.text ? -1 : a.candidate.text > b.candidate.text ? 1 : 0),
  );
  return out.slice(0, limit);
}
