import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { Layout } from '@/components/layout/Layout';
import { AttackPaths } from '@/pages/AttackPaths';
import { Dashboard } from '@/pages/Dashboard';
import { GraphExplorer } from '@/pages/GraphExplorer';
import { NotFound } from '@/pages/NotFound';
import { PathDetail } from '@/pages/PathDetail';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30_000,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="paths" element={<AttackPaths />} />
            <Route path="paths/:pathId" element={<PathDetail />} />
            <Route path="graph" element={<GraphExplorer />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
