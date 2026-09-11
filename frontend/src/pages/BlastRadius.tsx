import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';

import { ApiError } from '@/api/client';
import { useComputeBlastRadius, useBlastRadiusRun } from '@/api/blastRadius';
import { tierCodeForScore, useRiskTierConfigs } from '@/api/config';
import { useGraphNodes } from '@/api/graph';
import type { BlastDirection, BlastRadiusResponse, BlastReachedNode } from '@/api/types';
import { BlastRadiusTree, ROW_LIMIT } from '@/components/blast/BlastRadiusTree';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, formatDuration, formatPercent, formatScore, isTruthy } from '@/lib/format';
import { nodeColorVar, riskBgVar, riskColorVar } from '@/theme/applyRuntimeTheme';
import { fadeInUp, staggerContainer } from '@/theme/motion';
import './BlastRadius.css';

/** How many origin candidates the search offers at once. */
const SEARCH_RESULTS = 8;

/**
 * Starting hop cap, mirroring the engine's own default so the control opens on
 * the value the backend would have picked. The request always states the number
 * explicitly, so what the reader sees is what was searched.
 */
const DEFAULT_MAX_DEPTH = 6;
const DEPTH_CHOICES = [1, 2, 3, 4, 5, 6, 8, 10];

const DIRECTIONS: { code: BlastDirection; label: string; hint: string }[] = [
  { code: 'outbound', label: 'Reaches out to', hint: 'What losing this one thing leads to.' },
  { code: 'inbound', label: 'Can be reached from', hint: 'What is upstream of it — where an attack could arrive from. Computed over the same graph with every edge reversed.' },
  { code: 'both', label: 'Both', hint: 'Everything on either side, keeping whichever route is more likely.' },
];

function directionHint(direction: BlastDirection): string {
  return DIRECTIONS.find((entry) => entry.code === direction)?.hint ?? '';
}

export function BlastRadius() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [origin, setOrigin] = useState<{ id: string; label: string } | undefined>(undefined);
  const [direction, setDirection] = useState<BlastDirection>('outbound');
  const [maxDepth, setMaxDepth] = useState(DEFAULT_MAX_DEPTH);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  const compute = useComputeBlastRadius();
  const deepLinkedRun = Number(searchParams.get('run'));
  const stored = useBlastRadiusRun(
    !compute.data && Number.isFinite(deepLinkedRun) && deepLinkedRun > 0 ? deepLinkedRun : undefined,
  );

  // Small debounce so the node search doesn't fire on every keystroke.
  useEffect(() => {
    const handle = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(handle);
  }, [search]);

  const candidates = useGraphNodes({
    q: debouncedSearch || undefined,
    limit: SEARCH_RESULTS,
  });

  const data: BlastRadiusResponse | undefined = compute.data ?? stored.data;

  // A run read back from a deep link carries its own origin, so the controls
  // catch up to what is actually on screen rather than describing something else.
  useEffect(() => {
    if (!stored.data || compute.data) return;
    setOrigin({
      id: stored.data.origin_node_id,
      label: stored.data.origin?.display_name || stored.data.origin?.name || stored.data.origin_node_id,
    });
    setDirection(stored.data.direction);
    setMaxDepth(stored.data.max_depth);
  }, [stored.data, compute.data]);

  const handleRun = () => {
    if (!origin) return;
    compute.mutate(
      { origin_node_id: origin.id, direction, max_depth: maxDepth },
      { onSuccess: (result) => setSearchParams({ run: String(result.blast_run_id) }, { replace: true }) },
    );
  };

  const originLabel = origin?.label ?? '';

  return (
    <div className="blast-radius">
      <GlassPanel padding="lg" className="blast-radius__controls" {...fadeInUp()}>
        <div className="blast-radius__intro">
          <h2 className="blast-radius__title">Blast radius</h2>
          <p className="blast-radius__lede">
            Pick one host, account or credential and assume an attacker already owns it. This shows
            everything they could get to from there, and how easily.
          </p>
        </div>

        <div className="blast-radius__form">
          <label className="blast-radius__field blast-radius__field--search">
            <span className="blast-radius__field-label">Compromised node</span>
            <span className="blast-radius__search">
              <Icon name="search" />
              <input
                type="text"
                placeholder={originLabel || 'Search by name…'}
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
              {origin && (
                <span className="blast-radius__chosen" title={origin.id}>
                  {originLabel}
                </span>
              )}
            </span>
          </label>

          <label className="blast-radius__field">
            <span className="blast-radius__field-label">Direction</span>
            <select
              value={direction}
              onChange={(event) => setDirection(event.target.value as BlastDirection)}
            >
              {DIRECTIONS.map((entry) => (
                <option key={entry.code} value={entry.code}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>

          <label className="blast-radius__field">
            <span className="blast-radius__field-label">Hop limit</span>
            <select value={maxDepth} onChange={(event) => setMaxDepth(Number(event.target.value))}>
              {DEPTH_CHOICES.map((depth) => (
                <option key={depth} value={depth}>
                  {depth} {depth === 1 ? 'hop' : 'hops'}
                </option>
              ))}
            </select>
          </label>

          <button
            type="button"
            className="pill-button blast-radius__run"
            onClick={handleRun}
            disabled={!origin || compute.isPending}
          >
            {compute.isPending ? 'Working…' : 'Show blast radius'}
          </button>
        </div>

        <p className="blast-radius__hint">{directionHint(direction)}</p>

        {debouncedSearch && (
          <div className="blast-radius__candidates">
            {candidates.isLoading && <LoadingState variant="list" rows={3} />}
            {candidates.isError && <ErrorState message="The node list could not be loaded." />}
            {candidates.data?.items.length === 0 && (
              <p className="blast-radius__no-match">No node matches “{debouncedSearch}”.</p>
            )}
            <ul>
              {(candidates.data?.items ?? []).map((node) => (
                <li key={node.node_id}>
                  <button
                    type="button"
                    className={`blast-radius__candidate${node.node_id === origin?.id ? ' blast-radius__candidate--active' : ''}`}
                    onClick={() => {
                      setOrigin({ id: node.node_id, label: node.display_name || node.name });
                      setSearch('');
                      setDebouncedSearch('');
                    }}
                  >
                    <span className="blast-radius__candidate-dot" style={{ background: nodeColorVar(node.kind) }} />
                    <span className="blast-radius__candidate-kind">{node.kind}</span>
                    <span className="blast-radius__candidate-name">{node.display_name || node.name}</span>
                    {node.is_crown_jewel && <Icon name="crown" className="blast-radius__crown" />}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </GlassPanel>

      <Results
        data={data}
        isPending={compute.isPending || stored.isLoading}
        error={compute.error ?? stored.error}
      />
    </div>
  );
}

interface ResultsProps {
  data: BlastRadiusResponse | undefined;
  isPending: boolean;
  error: unknown;
}

function Results({ data, isPending, error }: ResultsProps) {
  if (isPending) return <LoadingState variant="list" rows={6} />;

  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return <EmptyState icon="circles" title="Nothing to compute against yet" description={error.message} />;
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

  if (!data) {
    return (
      <EmptyState
        icon="circles"
        title="Choose a node to start from"
        description="Search for a host, account or credential above. The result assumes that one thing is already in an attacker's hands and works out what follows."
      />
    );
  }

  if (data.items.length === 0) {
    return (
      <EmptyState
        icon="shield-check"
        title="Nothing follows from this node"
        description={`Within ${data.max_depth} hops, losing ${data.origin?.display_name || data.origin_node_id} gives an attacker no way on to anything else. That is a good result, not a missing one.`}
      />
    );
  }

  return <ReachedView data={data} />;
}

/**
 * One view rather than a stack of cards: the summary, the tree that shows every
 * reached node at once, the plain-language caption that explains what its
 * colours mean, and — for anyone who needs the exact figures or is reading with
 * a screen reader — the same set again as a compact list. A reader who has
 * never seen this product before should be able to read it top to bottom
 * without a glossary.
 */
function ReachedView({ data }: { data: BlastRadiusResponse }) {
  const { data: tiers = [] } = useRiskTierConfigs();

  const groups = useMemo(() => {
    const byDepth = new Map<number, BlastReachedNode[]>();
    for (const item of data.items) {
      const bucket = byDepth.get(item.depth);
      if (bucket) bucket.push(item);
      else byDepth.set(item.depth, [item]);
    }
    return [...byDepth.entries()].sort((a, b) => a[0] - b[0]);
  }, [data.items]);

  // How many nodes the diagram folds into its per-row "+N more" markers. Stated
  // in the caption rather than left for the reader to notice the counts not
  // adding up.
  const overflowed = useMemo(
    () => groups.reduce((total, [, nodes]) => total + Math.max(0, nodes.length - ROW_LIMIT), 0),
    [groups],
  );

  const originName = data.origin?.display_name || data.origin?.name || data.origin_node_id;

  return (
    <GlassPanel padding="lg" className="blast-radius__result" raised {...fadeInUp()}>
      <header className="blast-radius__summary">
        <div className="blast-radius__summary-lead">
          <span className="blast-radius__summary-label">If this were compromised</span>
          <span className="blast-radius__summary-origin" title={data.origin_node_id}>
            {data.origin?.kind && <span className="blast-radius__summary-kind">{data.origin.kind}</span>}
            {originName}
            {isTruthy(data.origin?.is_crown_jewel ?? 0) && <Icon name="crown" className="blast-radius__crown" />}
          </span>
        </div>

        <dl className="blast-radius__figures">
          <div>
            <dt>Things reached</dt>
            <dd>{formatCount(data.nodes_reached)}</dd>
          </div>
          <div>
            <dt>Crown jewels reached</dt>
            <dd className={data.crown_jewels_reached > 0 ? 'blast-radius__figure--alarm' : undefined}>
              {formatCount(data.crown_jewels_reached)}
            </dd>
          </div>
          <div>
            <dt>Worst outcome</dt>
            <dd className="blast-radius__figure--severity">
              {data.severity_score === null ? (
                '—'
              ) : (
                <>
                  <span>{formatScore(data.severity_score)}</span>
                  <span className="blast-radius__figure-suffix">/ 10</span>
                  {data.severity_tier_code && <RiskTierBadge code={data.severity_tier_code} size="sm" />}
                </>
              )}
            </dd>
          </div>
          <div>
            <dt>Searched</dt>
            <dd>
              {data.max_depth} {data.max_depth === 1 ? 'hop' : 'hops'}
              {data.duration_ms !== null && (
                <span className="blast-radius__figure-suffix">in {formatDuration(data.duration_ms)}</span>
              )}
            </dd>
          </div>
        </dl>
      </header>

      <p className="blast-radius__legend">
        Every circle is one thing the attacker could get to, hanging off the compromised node at
        the top. <strong>The further down the picture, the more steps it takes to get there.</strong>{' '}
        A circle&rsquo;s fill is what kind of thing it is — a host, an account, a credential — the
        same colours used everywhere else in faultline. The line dropping into it is how likely the
        attacker is to succeed at every step along the way: <strong>redder means easier for the
        attacker</strong>, using the same bands as the risk scores on the other screens. A gold ring
        marks a crown jewel. &ldquo;Worst outcome&rdquo; above is the highest-scoring single thing
        below, out of ten.
        {overflowed > 0 &&
          ` Each row draws at most ${ROW_LIMIT} circles: where more than that were reached, the
            likeliest are drawn and the rest are counted in a dashed “+N more” circle at the end of
            the row. ${formatCount(overflowed)} of ${formatCount(data.items.length)} are left out of
            the picture this way, and all of them are in the full list below.`}
        {data.truncated && ' This run hit its search budget, so the result is a lower bound.'}
      </p>

      <BlastRadiusTree
        origin={data.origin}
        originNodeId={data.origin_node_id}
        items={data.items}
      />

      <details className="blast-radius__full-list">
        <summary>
          Full list with exact numbers
          <span className="blast-radius__group-count">{formatCount(data.items.length)}</span>
        </summary>

        <div className="blast-radius__table">
        <div className="blast-radius__row blast-radius__row--head" aria-hidden="true">
          <span>Kind</span>
          <span>Reached</span>
          <span>Steps</span>
          <span>Chance an attacker gets here</span>
        </div>

        {groups.map(([depth, nodes]) => (
          <section key={depth} className="blast-radius__group">
            <h3 className="blast-radius__group-title">
              {depth} {depth === 1 ? 'step away' : 'steps away'}
              <span className="blast-radius__group-count">{formatCount(nodes.length)}</span>
            </h3>
            <motion.ul initial="initial" animate="animate" variants={staggerContainer()}>
              {nodes.map((node) => {
                // A node's chance of being reached is mapped onto the same 0-10
                // scale the risk tiers are defined on, exactly as the path flow
                // diagram maps a single hop's success chance -- one colour
                // vocabulary across the product, never a second one invented here.
                const tierCode = tierCodeForScore(node.p_reach * 10, tiers);
                return (
                  <motion.li key={node.node_id} variants={fadeInUp()}>
                    <div className="blast-radius__row">
                      <span className="blast-radius__kind">{node.kind ?? '—'}</span>
                      <span className="blast-radius__name" title={node.node_id}>
                        {node.name}
                        {isTruthy(node.is_crown_jewel) && (
                          <Icon name="crown" className="blast-radius__crown" />
                        )}
                      </span>
                      <span className="blast-radius__depth">{node.depth}</span>
                      <span className="blast-radius__chance">
                        <span
                          className="blast-radius__bar"
                          style={{ background: tierCode ? riskBgVar(tierCode) : undefined }}
                        >
                          <span
                            className="blast-radius__bar-fill"
                            style={{
                              width: `${Math.max(2, node.p_reach * 100)}%`,
                              background: tierCode ? riskColorVar(tierCode) : undefined,
                            }}
                          />
                        </span>
                        <span
                          className="blast-radius__chance-value"
                          style={tierCode ? { color: riskColorVar(tierCode) } : undefined}
                        >
                          {formatPercent(node.p_reach)}
                        </span>
                      </span>
                    </div>
                  </motion.li>
                );
              })}
            </motion.ul>
          </section>
        ))}
        </div>
      </details>

      <footer className="blast-radius__provenance">
        Run {data.blast_run_id} · graph version {data.graph_version_id} · scoring {data.scoring_version}
        {data.expansions !== null && ` · ${formatCount(data.expansions)} states examined`}
      </footer>
    </GlassPanel>
  );
}
