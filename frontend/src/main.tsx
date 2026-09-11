import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { applyRuntimeTheme } from '@/theme/applyRuntimeTheme';
import '@/theme/global.css';
import { App } from './App';

// Fire-and-forget: domain colour arrives whenever the config API answers, but
// the app must not block its first paint on a backend that may not be up
// (see docs/SCOPE.md D12 -- every consumer already falls back to a neutral
// token while this is in flight or fails).
void applyRuntimeTheme();

const container = document.getElementById('root');
if (!container) {
  throw new Error('Root element #root was not found in index.html.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
