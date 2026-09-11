import { useState, type TransitionEvent } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { IntroSplash } from '@/components/intro/IntroSplash';
import { Layout } from '@/components/layout/Layout';
import { AttackPaths } from '@/pages/AttackPaths';
import { Dashboard } from '@/pages/Dashboard';
import { GraphExplorer } from '@/pages/GraphExplorer';
import { NotFound } from '@/pages/NotFound';
import { PathDetail } from '@/pages/PathDetail';
import { Settings } from '@/pages/Settings';
import { prefersReducedMotion } from '@/theme/motion';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30_000,
    },
  },
});

// Shown once per browser tab session, not once ever -- a returning visitor in
// the same tab shouldn't replay it on every internal navigation, but a fresh
// tab (or a hard refresh) is treated as a new arrival.
const INTRO_SEEN_KEY = 'faultline:intro-seen';

function shouldShowIntro(): boolean {
  if (prefersReducedMotion()) return false;
  try {
    return window.sessionStorage.getItem(INTRO_SEEN_KEY) !== '1';
  } catch {
    // Private-browsing storage restrictions etc. -- fail toward showing it once rather than throwing.
    return true;
  }
}

export function App() {
  const [introActive, setIntroActive] = useState(shouldShowIntro);
  const [dashboardVisible, setDashboardVisible] = useState(() => !introActive);
  // Once the reveal's own transition finishes, its scale/opacity classes are
  // dropped for the rest of the session -- see the CSS comment on
  // .app-reveal--settled for why this can't just be the resting state of
  // .app-reveal--visible.
  const [revealSettled, setRevealSettled] = useState(() => !introActive);

  const handleIntroFinish = () => {
    try {
      window.sessionStorage.setItem(INTRO_SEEN_KEY, '1');
    } catch {
      // Nothing to do if storage is unavailable -- the intro will just replay next tab.
    }
    setDashboardVisible(true);
  };

  const handleRevealTransitionEnd = (event: TransitionEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget && event.propertyName === 'opacity') {
      setRevealSettled(true);
    }
  };

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {introActive && (
          <IntroSplash onFinish={handleIntroFinish} onExitComplete={() => setIntroActive(false)} />
        )}
        <div
          className={
            revealSettled
              ? 'app-reveal--settled'
              : `app-reveal${dashboardVisible ? ' app-reveal--visible' : ''}`
          }
          onTransitionEnd={handleRevealTransitionEnd}
        >
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="paths" element={<AttackPaths />} />
              <Route path="paths/:pathId" element={<PathDetail />} />
              <Route path="graph" element={<GraphExplorer />} />
              <Route path="settings" element={<Settings />} />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
