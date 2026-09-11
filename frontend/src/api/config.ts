import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type { NavItem, RiskTierConfig, Vocabularies } from './types';

/** Sidebar navigation, as rows the operator can add to or reorder without a rebuild. */
export function useNavItems() {
  return useQuery({
    queryKey: ['config', 'nav'],
    queryFn: () => apiGet<NavItem[]>('/config/nav'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

/** Risk tier bands (label, thresholds, colour) for the active scoring version. */
export function useRiskTierConfigs() {
  return useQuery({
    queryKey: ['config', 'risk-tiers'],
    queryFn: () => apiGet<RiskTierConfig[]>('/config/risk-tiers'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

/** Node-kind and edge-type styling vocabularies. */
export function useVocabularies() {
  return useQuery({
    queryKey: ['config', 'vocabularies'],
    queryFn: () => apiGet<Vocabularies>('/config/vocabularies'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

/** Convenience lookup from a risk tier code to its configured row. */
export function useRiskTierMap(): Map<string, RiskTierConfig> {
  const { data } = useRiskTierConfigs();
  const map = new Map<string, RiskTierConfig>();
  for (const tier of data ?? []) map.set(tier.code, tier);
  return map;
}
