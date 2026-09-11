import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Outlet, useLocation } from 'react-router-dom';

import { fade } from '@/theme/motion';
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
            <AnimatePresence mode="wait" initial={false}>
              <motion.div key={location.pathname} {...fade()}>
                <Outlet />
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
        <StatusBar />
      </div>
    </div>
  );
}
