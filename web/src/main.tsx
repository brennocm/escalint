import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { applyTheme, resolveTheme } from './design/tokens';

const media = window.matchMedia('(prefers-color-scheme: dark)');
const syncTheme = () => {
  applyTheme(document.documentElement, resolveTheme('system', media.matches));
};
syncTheme();
media.addEventListener('change', syncTheme);

const container = document.getElementById('root');
if (!container) {
  throw new Error('missing #root element');
}
createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
