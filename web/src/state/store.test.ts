import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { bindLocation, createAppStore, navigate } from './app';
import { createStore, memo, memo2, useStore } from './store';
import { to } from './route';

describe('store', () => {
  it('notifies only on change', () => {
    const s = createStore({ n: 1 });
    const l = vi.fn();
    const off = s.subscribe(l);
    s.set((x) => x);
    expect(l).not.toHaveBeenCalled();
    s.set((x) => ({ n: x.n + 1 }));
    expect(l).toHaveBeenCalledTimes(1);
    off();
    s.set(() => ({ n: 9 }));
    expect(l).toHaveBeenCalledTimes(1);
    expect(s.get().n).toBe(9);
  });
  it('drives React through useStore', () => {
    const s = createStore({ n: 1, other: 'x' });
    const { result } = renderHook(() => useStore(s, (x) => x.n));
    expect(result.current).toBe(1);
    act(() => {
      s.set((x) => ({ ...x, n: 2 }));
    });
    expect(result.current).toBe(2);
  });
  it('memoizes by reference', () => {
    const f = vi.fn((a: { v: number }) => a.v * 2);
    const m = memo(f);
    const a = { v: 2 };
    expect(m(a)).toBe(4);
    expect(m(a)).toBe(4);
    expect(f).toHaveBeenCalledTimes(1);
    m({ v: 2 });
    expect(f).toHaveBeenCalledTimes(2);
    const g = vi.fn((x: number, y: number) => x + y);
    const m2 = memo2(g);
    m2(1, 2);
    m2(1, 2);
    m2(1, 3);
    expect(g).toHaveBeenCalledTimes(2);
  });
});

describe('location binding', () => {
  it('syncs route and hash both ways', () => {
    window.history.replaceState(null, '', '#/findings');
    const store = createAppStore(window.location.hash);
    expect(store.get().route.view).toBe('findings');
    const off = bindLocation(store);
    navigate(store, to('atlas'));
    expect(window.location.hash).toBe('#/atlas');
    const push = vi.spyOn(window.history, 'pushState');
    const replace = vi.spyOn(window.history, 'replaceState');
    navigate(store, { ...to('atlas'), camera: { x: 1, y: 2, zoom: 1.5 } });
    expect(replace).toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
    window.location.hash = '#/exposure';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    expect(store.get().route.view).toBe('exposure');
    window.location.hash = '#/nope';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    expect(store.get().route.view).toBe('overview');
    expect(store.get().notice).toMatch(/invalid link/);
    off();
    push.mockRestore();
    replace.mockRestore();
  });
  it('starts with a notice for invalid links', () => {
    expect(createAppStore('#/bogus').get().notice).toMatch(/invalid link/);
  });
});
