import { useRiskTierConfigs } from '@/api/config';
import { GlassPanel } from '@/components/ui/GlassPanel';
import './PathFiltersBar.css';

export interface PathFiltersState {
  tier: string;
  crownJewelsOnly: boolean;
  maxHops: string;
}

interface PathFiltersBarProps {
  value: PathFiltersState;
  onChange: (next: PathFiltersState) => void;
  resultCount?: number;
  total?: number;
}

export function PathFiltersBar({ value, onChange, resultCount, total }: PathFiltersBarProps) {
  const { data: tiers } = useRiskTierConfigs();

  return (
    <GlassPanel padding="sm" className="path-filters">
      <div className="path-filters__group">
        <label className="path-filters__label" htmlFor="filter-tier">
          Risk tier
        </label>
        <select
          id="filter-tier"
          value={value.tier}
          onChange={(event) => onChange({ ...value, tier: event.target.value })}
        >
          <option value="">All tiers</option>
          {(tiers ?? []).map((tier) => (
            <option key={tier.code} value={tier.code}>
              {tier.label}
            </option>
          ))}
        </select>
      </div>

      <div className="path-filters__group">
        <label className="path-filters__label" htmlFor="filter-max-hops">
          Max hops
        </label>
        <input
          id="filter-max-hops"
          type="number"
          min={1}
          placeholder="Any"
          value={value.maxHops}
          onChange={(event) => onChange({ ...value, maxHops: event.target.value })}
        />
      </div>

      <label className="path-filters__checkbox">
        <input
          type="checkbox"
          checked={value.crownJewelsOnly}
          onChange={(event) => onChange({ ...value, crownJewelsOnly: event.target.checked })}
        />
        Crown jewels only
      </label>

      {typeof resultCount === 'number' && (
        <span className="path-filters__count">
          {resultCount.toLocaleString()}
          {typeof total === 'number' && total !== resultCount ? ` of ${total.toLocaleString()}` : ''} paths
        </span>
      )}
    </GlassPanel>
  );
}
