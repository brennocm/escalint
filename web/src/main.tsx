import './fonts.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createAppStore } from './state/app';

const container = document.getElementById('root');
if (!container) {
  throw new Error('missing #root element');
}
const store = createAppStore(window.location.hash);
createRoot(container).render(
  <StrictMode>
    <App store={store} />
  </StrictMode>,
);
