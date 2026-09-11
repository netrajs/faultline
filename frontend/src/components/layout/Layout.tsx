import { useState } from 'react';
import { motion } from 'framer-motion';
import { Outlet, useLocation } from 'react-router-dom';

import { duration, easeStandard } from '@/theme/motion';
import { Sidebar } from './Sidebar';
import { StarField } from './StarField';
import { Topbar } from './Topbar';
import { StatusBar } from './StatusBar';
import './Layout.css';

const COLLAPSE_STORAGE_KEY = 'faultline:sidebar-collapsed';

// Collapsed by default -- an explicit stored '0' is the only thing that
// expands it, so a first-time visitor sees the icon rail rather than the
// full labeled sidebar.
function readStoredCollapsed(): boolean {
  try {
    return window.localStorage.getItem(COLLAPSE_STORAGE_KEY) !== '0';
  } catch {
    return true;
  }
}

export function Layout() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState<boolean>(readStoredCollapsed);

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem(COLLAPSE_STORAGE_KEY, next ? '1' : '0');
      } catch {
        // Private browsing / storage disabled -- the toggle still works for this session.
      }
      return next;
    });
  };

  return (
    <div className="app-shell">
      <StarField />
      <Sidebar collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />
      <div className={`app-shell__body ${collapsed ? 'app-shell__body--collapsed' : ''}`}>
        <Topbar />
        <main className="app-shell__main">
          <div className="app-shell__content">
            {/*
              Enter-only fade, deliberately without AnimatePresence. Wrapping this in
              AnimatePresence to also animate the OUTGOING page's exit means both the
              old and new route content are mounted at once while the old one fades
              out -- and since neither is taken out of normal document flow, the two
              stack vertically, doubling the container's height and pushing the new
              (fully visible) content below the fold. The page then looks blank until
              a manual reload skips the transition and mounts only the current route.
              A route swap doesn't need its old content to visibly animate away --
              React Router already replaces it as part of the same update -- so this
              only animates the incoming page in.
            */}
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: duration('base'), ease: easeStandard }}
            >
              <Outlet />
            </motion.div>
          </div>
        </main>
        <StatusBar />
      </div>
    </div>
  );
}
