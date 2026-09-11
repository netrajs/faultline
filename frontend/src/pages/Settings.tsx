import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { ApiError } from '@/api/client';
import { useRegenerateGraph, useSettingsOverview } from '@/api/settings';
import type { RegenerateResponse } from '@/api/types';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, formatPercent } from '@/lib/format';
import './Settings.css';

type Scale = 'small' | 'medium' | 'large';

const SCALE_OPTIONS: { value: Scale; label: string; hint: string }[] = [
  { value: 'small', label: 'Small', hint: '4 planted opportunities' },
  { value: 'medium', label: 'Medium', hint: '8 planted opportunities (default)' },
  { value: 'large', label: 'Large', hint: '16 planted opportunities' },
];

function formatDate(value: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

/** DECIMAL columns arrive as strings over JSON (see api/types.ts) -- parse before formatting. */
function pct(value: string | number): string {
  return formatPercent(Number(value));
}

export function Settings() {
  const overview = useSettingsOverview();
  const regenerate = useRegenerateGraph();
  const navigate = useNavigate();

  const [scale, setScale] = useState<Scale>('medium');
  const [seedInput, setSeedInput] = useState('');
  const [result, setResult] = useState<RegenerateResponse | null>(null);

  if (overview.isLoading) {
    return (
      <div className="settings-page">
        <LoadingState variant="cards" rows={4} />
        <LoadingState variant="list" rows={6} />
      </div>
    );
  }

  if (overview.isError) {
    const error = overview.error;
    if (error instanceof ApiError && error.status === 404) {
      return <EmptyState icon="settings" title="No active graph version" description={error.message} />;
    }
    return (
      <ErrorState
        message={
          error instanceof ApiError
            ? error.message
            : 'The API could not be reached. Confirm the backend is running and CORS allows this origin.'
        }
      />
    );
  }

  const data = overview.data;
  if (!data) return null;

  const defaultThreatModel = data.threat_models.find((model) => model.is_default === 1) ?? data.threat_models[0];
  const weights = data.scoring.config;

  const handleRegenerate = () => {
    const seedNote = seedInput.trim() ? `seed ${seedInput.trim()}` : 'a random seed';
    const confirmed = window.confirm(
      `This generates a brand new synthetic graph (${scale} scale, ${seedNote}) and makes it the active one. ` +
        'Every discovered path, chokepoint, and analysis run computed against the current graph stops being ' +
        'comparable once this finishes. Continue?',
    );
    if (!confirmed) return;

    setResult(null);
    regenerate.mutate(
      {
        scale,
        seed: seedInput.trim() ? Number(seedInput.trim()) : undefined,
      },
      { onSuccess: (response) => setResult(response) },
    );
  };

  return (
    <div className="settings-page">
      {/* Current state -- one summary block, not one stat card per fact. */}
      <GlassPanel padding="lg" raised className="settings-section">
        <div className="settings-section__header">
          <Icon name="database" className="settings-section__icon" />
          <div>
            <h2 className="settings-section__title">Current state</h2>
            <p className="settings-section__intro">
              What faultline is running against right now: the active demo graph, the scoring configuration that
              produced every risk score you've seen, and which integrations are live versus falling back to an
              offline default.
            </p>
          </div>
        </div>

        <dl className="settings-summary">
          <div className="settings-summary__row">
            <dt>Active graph</dt>
            <dd>
              <span className="settings-summary__primary">
                #{data.graph_version.id} — {data.graph_version.label}
              </span>
              <span className="settings-summary__secondary">
                {formatCount(data.graph_version.node_count)} nodes · {formatCount(data.graph_version.edge_count)} edges
                {' · '}seed {data.graph_version.seed ?? '—'} · generated {formatDate(data.graph_version.created_at)}
              </span>
            </dd>
          </div>

          <div className="settings-summary__row">
            <dt>Scoring configuration</dt>
            <dd>
              <span className="settings-summary__primary">
                {weights.version} — {weights.label}
              </span>
              <span className="settings-summary__secondary">{weights.description}</span>
            </dd>
          </div>

          <div className="settings-summary__row">
            <dt>Default threat model</dt>
            <dd>
              <span className="settings-summary__primary">{defaultThreatModel?.label ?? '—'}</span>
              <span className="settings-summary__secondary">
                {defaultThreatModel?.description}
                {data.threat_models.length > 1 && (
                  <> · {data.threat_models.length} threat models configured in total</>
                )}
              </span>
            </dd>
          </div>

          <div className="settings-summary__row">
            <dt>Narration</dt>
            <dd>
              <span className={`settings-badge ${data.narration_available ? 'settings-badge--on' : 'settings-badge--off'}`}>
                <Icon name={data.narration_available ? 'check' : 'ban'} />
                {data.narration_available ? 'Live model available' : 'Offline template fallback'}
              </span>
            </dd>
          </div>

          <div className="settings-summary__row">
            <dt>Anchor mode</dt>
            <dd>
              <span className="settings-badge settings-badge--neutral">
                <Icon name="link" />
                {data.anchor_mode}
              </span>
            </dd>
          </div>
        </dl>
      </GlassPanel>

      {/* How paths are scored -- one table, not one card per technique (D13). */}
      <GlassPanel padding="lg" className="settings-section">
        <div className="settings-section__header">
          <Icon name="gauge" className="settings-section__icon" />
          <div>
            <h2 className="settings-section__title">How paths are scored</h2>
            <p className="settings-section__intro">
              Every attack path's risk score is built from these numbers, read from the active scoring
              configuration above — nothing about how a path is scored is decided in the interface itself. Each
              technique below has a <strong>base success chance</strong> (how often it works before any
              situational adjustments, such as a weak credential or missing MFA) and a{' '}
              <strong>base detectability</strong> (how likely defenders are to notice it happening). Those two
              numbers, combined per hop and then weighted{' '}
              {pct(weights.w_likelihood)} for likelihood, {pct(weights.w_impact)} for target impact, and{' '}
              {pct(weights.w_stealth)} for staying undetected, are what produces the 0–10 score shown everywhere
              else in the product.
            </p>
          </div>
        </div>

        <div className="settings-table-scroll">
          <table className="settings-table">
            <thead>
              <tr>
                <th>Technique</th>
                <th>Base success chance</th>
                <th>Base detectability</th>
              </tr>
            </thead>
            <tbody>
              {data.scoring.baselines.map((baseline) => (
                <tr key={baseline.technique_code}>
                  <td>
                    <span className="settings-table__technique">{baseline.technique_name}</span>
                    {baseline.rationale && <span className="settings-table__rationale">{baseline.rationale}</span>}
                  </td>
                  <td className="settings-table__number">{pct(baseline.base_p_succ)}</td>
                  <td className="settings-table__number">{pct(baseline.base_detectability)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </GlassPanel>

      {/* Regenerate the demo data -- confirmation, loading, and success states. */}
      <GlassPanel padding="lg" className="settings-section">
        <div className="settings-section__header">
          <Icon name="refresh" className="settings-section__icon" />
          <div>
            <h2 className="settings-section__title">Regenerate the demo data</h2>
            <p className="settings-section__intro">
              Builds a brand new synthetic identity/asset graph and makes it the active one. This is a real,
              disruptive action: the current graph, every path discovered against it, and every chokepoint or
              blast-radius result computed from those paths stop being comparable the moment a new graph goes
              active. Use it between demos, not mid-walkthrough.
            </p>
          </div>
        </div>

        <div className="settings-regenerate">
          <div className="settings-regenerate__controls">
            <label className="settings-regenerate__field">
              <span className="settings-regenerate__label">Scale</span>
              <select value={scale} onChange={(event) => setScale(event.target.value as Scale)} disabled={regenerate.isPending}>
                {SCALE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label} — {option.hint}
                  </option>
                ))}
              </select>
            </label>

            <label className="settings-regenerate__field">
              <span className="settings-regenerate__label">Seed (optional)</span>
              <input
                type="number"
                placeholder="Random"
                value={seedInput}
                onChange={(event) => setSeedInput(event.target.value)}
                disabled={regenerate.isPending}
              />
            </label>

            <button
              type="button"
              className="pill-button pill-button--primary settings-regenerate__button"
              onClick={handleRegenerate}
              disabled={regenerate.isPending}
            >
              <Icon name={regenerate.isPending ? 'loader-2' : 'refresh'} className={regenerate.isPending ? 'settings-spin' : ''} />
              {regenerate.isPending ? 'Generating…' : 'Regenerate demo graph'}
            </button>
          </div>

          {regenerate.isPending && (
            <p className="settings-regenerate__status">
              Running the generator. Larger scales can take a little while — this page will update as soon as it
              finishes.
            </p>
          )}

          {regenerate.isError && (
            <ErrorState
              title="Generation failed"
              message={
                regenerate.error instanceof ApiError
                  ? regenerate.error.message
                  : 'Could not reach the API to start generation.'
              }
            />
          )}

          {result && (
            <div className="settings-regenerate__result">
              <Icon name="circle-check" className="settings-regenerate__result-icon" />
              <div className="settings-regenerate__result-body">
                <span className="settings-regenerate__result-title">
                  Graph version #{result.graph_version.id} is now active
                </span>
                <span className="settings-regenerate__result-detail">
                  {formatCount(result.graph_version.node_count)} nodes · {formatCount(result.graph_version.edge_count)}{' '}
                  edges · seed {result.seed} · {result.scale} scale
                </span>
              </div>
              <button type="button" className="pill-button" onClick={() => navigate('/graph')}>
                View in Graph Explorer <Icon name="arrow-narrow-right" />
              </button>
            </div>
          )}
        </div>
      </GlassPanel>
    </div>
  );
}
