/**
 * Response shapes and query hooks for /api/settings/* (see
 * backend/app/routers/settings.py).
 *
 * overview() is one aggregated read -- the active scoring configuration, the
 * threat model catalogue, the anchor/narration integration state, and the
 * active graph version -- so the Settings screen makes one round trip
 * instead of stitching together /api/config/scoring, /api/config/threat-models,
 * /api/graph/version, and a settings-only endpoint for the rest.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiGet, apiPost } from './client';
import type { RegenerateRequest, RegenerateResponse, SettingsOverview } from './types';

export function useSettingsOverview() {
  return useQuery({
    queryKey: ['settings', 'overview'],
    queryFn: () => apiGet<SettingsOverview>('/settings/overview'),
    retry: 1,
  });
}

export function useRegenerateGraph() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: RegenerateRequest) => apiPost<RegenerateResponse>('/settings/regenerate', body),
    onSuccess: () => {
      // The active graph version changed under every other screen's feet --
      // invalidate broadly rather than trying to enumerate every query key
      // that embeds a graph_version, run id, or score computed against it.
      queryClient.invalidateQueries();
    },
  });
}
