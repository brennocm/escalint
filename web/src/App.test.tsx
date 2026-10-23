import { act, fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';
import { vulnerable } from './data/fixtures';
import { createAppStore } from './state/app';

describe('App', () => {
  it('shows an error state when loading fails', async () => {
    const store = createAppStore('');
    render(
      <App
        store={store}
        load={() => Promise.reject(new Error('unsupported schema_version "9"'))}
      />,
    );
    expect((await screen.findByRole('alert')).textContent).toContain('unsupported schema_version');
  });

  it('loads the analysis and renders the shell', async () => {
    window.history.replaceState(null, '', '#/');
    const store = createAppStore('');
    render(<App store={store} load={() => Promise.resolve(vulnerable)} />);
    expect(await screen.findByRole('navigation', { name: 'Views' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Overview' }).getAttribute('aria-current')).toBe(
      'page',
    );
  });

  it('opens the command palette with Ctrl+K and navigates', async () => {
    window.history.replaceState(null, '', '#/');
    const store = createAppStore('');
    render(<App store={store} load={() => Promise.resolve(vulnerable)} />);
    await screen.findByRole('navigation', { name: 'Views' });
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const box = await screen.findByRole('combobox');
    fireEvent.change(box, { target: { value: 'Findings' } });
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(store.get().route.view).toBe('findings');
    expect(screen.queryByRole('combobox')).toBeNull();
  });

  it('toggles help, theme and pseudonyms from the keyboard', async () => {
    const store = createAppStore('');
    render(<App store={store} load={() => Promise.resolve(vulnerable)} />);
    await screen.findByRole('navigation', { name: 'Views' });
    act(() => {
      fireEvent.keyDown(window, { key: '?' });
    });
    expect(screen.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeTruthy();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.keyDown(window, { key: 't' });
    expect(store.get().theme).toBe('light');
    fireEvent.keyDown(window, { key: 'p' });
    expect(store.get().pseudonyms).toBe(true);
    fireEvent.keyDown(window, { key: 'g' });
    fireEvent.keyDown(window, { key: 'a' });
    expect(store.get().route.view).toBe('atlas');
  });
});
