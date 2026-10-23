import { describe, expect, it } from 'vitest';
import { score, search, type Candidate } from './fuzzy';

const c = (text: string, tier = 3, key = text): Candidate => ({
  key,
  kind: 'node',
  text,
  label: text,
  detail: '',
  tier,
});

describe('score', () => {
  it('ranks prefix > word start > subsequence', () => {
    expect(score('adm', 'admin-role').score).toBe(3);
    expect(score('adm', 'role/admin').score).toBe(2);
    expect(score('adm', 'readOnlyAdmin').score).toBe(2);
    expect(score('adm', 'aXdXm').score).toBe(1);
    expect(score('adm', 'dma').score).toBe(0);
    expect(score('', 'x').score).toBe(0);
  });
  it('reports matched positions', () => {
    expect(score('rol', 'my-role').positions).toEqual([3, 4, 5]);
    expect(score('ae', 'admin-eu').positions).toEqual([0, 6]);
  });
  it('is case-insensitive', () => {
    expect(score('ADMIN', 'admin').score).toBe(3);
  });
  it('does not take a mid-word substring as a word start', () => {
    expect(score('min', 'admin').score).toBe(1);
  });
});

describe('search', () => {
  it('orders by class, then tier, then length', () => {
    const got = search('admin', [
      c('role/admin', 3),
      c('admin-role-long', 3),
      c('admin', 1),
      c('xadminx', 0),
      c('role/admin2', 0),
    ]);
    expect(got.map((m) => m.candidate.text)).toEqual([
      'admin',
      'admin-role-long',
      'role/admin2',
      'role/admin',
      'xadminx',
    ]);
  });
  it('limits and ignores blank queries', () => {
    const many = Array.from({ length: 50 }, (_, i) => c(`user-${String(i)}`));
    expect(search('user', many, 5)).toHaveLength(5);
    expect(search('   ', many)).toEqual([]);
  });
});
