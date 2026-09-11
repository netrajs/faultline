import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Self-hosted, so the type never silently falls back to a system font when
// no network reaches a font CDN. Manrope carries body copy and UI chrome;
// Space Grotesk (a distinct family, not just a heavier weight of the same
// one) carries headings and the big numeric displays, so the dashboard has
// an actual typographic hierarchy instead of one face at different sizes.
import '@fontsource-variable/manrope';
import '@fontsource-variable/space-grotesk';
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
