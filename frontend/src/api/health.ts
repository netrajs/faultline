import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type { HealthResponse } from './types';

/** Store reachability and the active graph version, polled for the status bar. */
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => apiGet<HealthResponse>('/health'),
    refetchInterval: 20_000,
    retry: 1,
  });
}
