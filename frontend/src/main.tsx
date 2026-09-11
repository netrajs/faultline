import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Self-hosted, so the type never silently falls back to a system font when
// no network reaches a font CDN -- 'Inter' in tokens.css was resolving to
// Segoe UI on every machine without it installed, which was most of them.
import '@fontsource-variable/inter';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/700.css';

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
