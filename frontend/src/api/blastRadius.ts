import { useMutation, useQuery } from '@tanstack/react-query';

import { apiGet, apiPost } from './client';
import type { BlastRadiusRequest, BlastRadiusResponse } from './types';

/**
 * Computing a blast radius is a POST because it writes: every run lands in
 * blast_radius_run and stays addressable by id, so a result can be revisited
 * or linked to instead of existing only in whoever's browser produced it.
 */
export function useComputeBlastRadius() {
  return useMutation({
    mutationFn: (request: BlastRadiusRequest) =>
      apiPost<BlastRadiusResponse>('/blast-radius', request),
  });
}

/** Reads a stored run back, which is what makes a deep link to one work. */
export function useBlastRadiusRun(blastRunId: number | undefined) {
  return useQuery({
    queryKey: ['blast-radius', blastRunId],
    queryFn: () => apiGet<BlastRadiusResponse>(`/blast-radius/${blastRunId as number}`),
    enabled: Boolean(blastRunId),
    retry: 1,
  });
}
