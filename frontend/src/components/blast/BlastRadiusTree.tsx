import { useMemo, useState } from 'react';

import { tierCodeForScore, useRiskTierConfigs, useVocabularies } from '@/api/config';
import type { BlastRadiusOrigin, BlastReachedNode } from '@/api/types';
import { Icon } from '@/components/ui/Icon';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { formatCount, formatPercent, isTruthy, shortId } from '@/lib/format';
import { nodeColorVar } from '@/theme/applyRuntimeTheme';
import './BlastRadiusTree.css';

const NODE_RADIUS = 18;
const ORIGIN_RADIUS = 26;
const NODE_SPACING = 132;
const ROW_HEIGHT = 118;
/** Vertical gap between a row's rail and the circles hanging off it. */
const RAIL_DROP = 36;
const ORIGIN_Y = 44;
/** Left strip reserved for the "N steps away" row labels, so they never sit under a node. */
const GUTTER = 104;
const MARGIN_X = 72;
const BOTTOM_PADDING = 54;

/**
 * How many nodes one depth row draws before it stops and counts the rest.
 *
 * A radius on a real graph fans out fast — a single row can hold thirty or more
 * nodes, and thirty labels in a row is a wall of text nobody reads. The row
 * keeps the ones an attacker is most likely to reach and says plainly how many
 * it left out; the full list with exact numbers sits below the diagram, so
 * nothing is actually hidden, only moved out of the picture.
 */
export const ROW_LIMIT = 12;

const CROWN_STROKE = '#d97706';

interface BlastRadiusTreeProps {
  origin: BlastRadiusOrigin | null;
  originNodeId: string;
  items: BlastReachedNode[];
}

interface Placed {
  node: BlastReachedNode;
  x: number;
  y: number;
  tierCode: string | undefined;
}

interface Row {
  depth: number;
  total: number;
  placed: Placed[];
  hidden: number;
  railY: number;
  railFrom: number;
  railTo: number;
  overflowX: number | null;
}

function truncate(text: string, max = 13): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * Everything a compromise of one node leads to, drawn as one node-and-edge
 * tree instead of a list.
 *
 * The origin sits at the top. Below it each depth gets its own row, so how far
 * down the picture a thing sits *is* how many steps an attacker needs to get
 * there — the one dimension the reader has to understand before anything else
 * makes sense. Rows are joined by a trunk from the origin, because every row
 * below the first is only reachable through the ones above it.
 *
 * The colours are the two already in use elsewhere in faultline, not a third
 * invented here. A circle is filled by asset kind, exactly as the Graph
 * Explorer and the attack-path flow diagram fill theirs, so a Host is the same
 * colour on every screen. The line dropping into a circle is coloured by that
 * node's own chance of being reached, mapped onto the risk-tier bands with the
 * same `tierCodeForScore` the path diagram uses for a single hop — so the easy
 * wins and the long shots are separable without clicking anything.
 */
export function BlastRadiusTree({ origin, originNodeId, items }: BlastRadiusTreeProps) {
  const { data: tiers = [] } = useRiskTierConfigs();
  const { data: vocab } = useVocabularies();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const nodeKindByCode = useMemo(
    () => new Map((vocab?.node_kinds ?? []).map((kind) => [kind.code, kind])),
    [vocab],
  );

  const { rows, width, height, centreX } = useMemo(() => {
    const byDepth = new Map<number, BlastReachedNode[]>();
    for (const item of items) {
      const bucket = byDepth.get(item.depth);
      if (bucket) bucket.push(item);
      else byDepth.set(item.depth, [item]);
    }

    const depths = [...byDepth.keys()].sort((a, b) => a - b);
    // A row keeps the most reachable nodes, and a crown jewel is never the one
    // dropped: it is the whole reason anyone opened this screen.
    const kept = depths.map((depth) => {
      const all = [...(byDepth.get(depth) ?? [])].sort((a, b) => {
        const crown = Number(isTruthy(b.is_crown_jewel)) - Number(isTruthy(a.is_crown_jewel));
        if (crown !== 0) return crown;
        if (b.p_reach !== a.p_reach) return b.p_reach - a.p_reach;
        return a.node_id.localeCompare(b.node_id);
      });
      return { depth, all, shown: all.slice(0, ROW_LIMIT) };
    });

    // The widest row sets the canvas; every other row is centred inside it, so
    // the trunk stays vertical and the picture reads as one tree.
    const widestSlots = kept.reduce(
      (most, row) => Math.max(most, row.shown.length + (row.all.length > row.shown.length ? 1 : 0)),
      1,
    );
    const contentWidth = Math.max(0, widestSlots - 1) * NODE_SPACING;
    const canvasWidth = GUTTER + contentWidth + MARGIN_X * 2;
    const centre = GUTTER + MARGIN_X + contentWidth / 2;

    const built: Row[] = kept.map((row, index) => {
      const hidden = row.all.length - row.shown.length;
      const slots = row.shown.length + (hidden > 0 ? 1 : 0);
      const rowWidth = Math.max(0, slots - 1) * NODE_SPACING;
      const startX = centre - rowWidth / 2;
      const y = ORIGIN_Y + (index + 1) * ROW_HEIGHT;

      const placed: Placed[] = row.shown.map((node, i) => ({
        node,
        x: startX + i * NODE_SPACING,
        y,
        // The chance of reaching a node is a probability, and the tier bands are
        // defined on the 0-10 risk scale, so it is scaled the same way the path
        // diagram scales a single hop's success chance.
        tierCode: tierCodeForScore(node.p_reach * 10, tiers),
      }));

      return {
        depth: row.depth,
        total: row.all.length,
        placed,
        hidden,
        railY: y - RAIL_DROP,
        railFrom: Math.min(startX, centre),
        railTo: Math.max(startX + rowWidth, centre),
        overflowX: hidden > 0 ? startX + rowWidth : null,
      };
    });

    return {
      rows: built,
      width: canvasWidth,
      height: ORIGIN_Y + built.length * ROW_HEIGHT + BOTTOM_PADDING,
      centreX: centre,
    };
  }, [items, tiers]);

  const originName = origin?.display_name || origin?.name || originNodeId;
  const originKind = origin?.kind ? nodeKindByCode.get(origin.kind) : undefined;
  const lastRailY = rows[rows.length - 1]?.railY ?? ORIGIN_Y;

  const selected = items.find((item) => item.node_id === selectedId);
  const selectedTier = selected ? tierCodeForScore(selected.p_reach * 10, tiers) : undefined;

  const kindsPresent = (vocab?.node_kinds ?? []).filter((kind) =>
    items.some((item) => item.kind === kind.code),
  );

  return (
    <div className="blast-tree">
      <div className="blast-tree__scroll">
        <svg
          className="blast-tree__svg"
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`Blast radius tree. ${originName} sits at the top; ${formatCount(items.length)} things it can lead to are arranged in rows below it, one row per number of steps away.`}
        >
          <defs>
            {tiers.map((tier) => (
              <marker
                key={tier.code}
                id={`blast-tree-arrow-${tier.code}`}
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M0,0 L10,5 L0,10 z" fill={tier.ui_color} />
              </marker>
            ))}
          </defs>

          {/* The trunk: every row below the first is only reachable through the
              ones above it, so one line carries the eye down the depths. */}
          {rows.length > 0 && (
            <line
              x1={centreX}
              y1={ORIGIN_Y + ORIGIN_RADIUS}
              x2={centreX}
              y2={lastRailY}
              className="blast-tree__trunk"
            />
          )}

          {rows.map((row) => (
            <g key={row.depth}>
              <line
                x1={row.railFrom}
                y1={row.railY}
                x2={row.railTo}
                y2={row.railY}
                className="blast-tree__rail"
              />
              <text x={GUTTER - 16} y={row.railY + 4} className="blast-tree__row-label" textAnchor="end">
                {row.depth} {row.depth === 1 ? 'step' : 'steps'}
              </text>
              <text x={GUTTER - 16} y={row.railY + 20} className="blast-tree__row-count" textAnchor="end">
                {formatCount(row.total)}
              </text>

              {row.placed.map((entry) => {
                const kind = entry.node.kind ? nodeKindByCode.get(entry.node.kind) : undefined;
                const tier = tiers.find((t) => t.code === entry.tierCode);
                const stroke = tier?.ui_color ?? 'var(--text-muted)';
                const isCrown = isTruthy(entry.node.is_crown_jewel);
                const isActive = entry.node.node_id === selectedId;

                return (
                  <g
                    key={entry.node.node_id}
                    className={`blast-tree__node${isActive ? ' blast-tree__node--active' : ''}`}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isActive}
                    onClick={() => setSelectedId(isActive ? null : entry.node.node_id)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setSelectedId(isActive ? null : entry.node.node_id);
                      }
                    }}
                  >
                    {/* Thin line, generous target: the drop is 2px wide but the
                        click area should not be. */}
                    <line
                      x1={entry.x}
                      y1={row.railY}
                      x2={entry.x}
                      y2={entry.y + NODE_RADIUS + 34}
                      className="blast-tree__hit"
                    />
                    <line
                      x1={entry.x}
                      y1={row.railY}
                      x2={entry.x}
                      y2={entry.y - NODE_RADIUS - 4}
                      className="blast-tree__drop"
                      stroke={stroke}
                      strokeWidth={isActive ? 3.5 : 2.25}
                      markerEnd={entry.tierCode ? `url(#blast-tree-arrow-${entry.tierCode})` : undefined}
                    />
                    <circle
                      cx={entry.x}
                      cy={entry.y}
                      r={NODE_RADIUS}
                      className="blast-tree__circle"
                      fill={kind ? kind.ui_color : 'var(--text-muted)'}
                      stroke={isCrown ? CROWN_STROKE : 'var(--bg-card)'}
                      strokeWidth={isCrown ? 3 : 2}
                    />
                    {isCrown && (
                      <text
                        x={entry.x}
                        y={entry.y + 5}
                        textAnchor="middle"
                        className="blast-tree__crown"
                        aria-label="crown jewel"
                      >
                        ♛
                      </text>
                    )}
                    <text
                      x={entry.x}
                      y={entry.y + NODE_RADIUS + 17}
                      textAnchor="middle"
                      className="blast-tree__node-label"
                    >
                      {truncate(entry.node.name)}
                    </text>
                    <text
                      x={entry.x}
                      y={entry.y + NODE_RADIUS + 31}
                      textAnchor="middle"
                      className="blast-tree__node-chance"
                      fill={stroke}
                    >
                      {formatPercent(entry.node.p_reach)}
                    </text>
                    <title>
                      {`${entry.node.name} (${entry.node.kind ?? 'unknown kind'}) — ${entry.node.depth} ${entry.node.depth === 1 ? 'step' : 'steps'} away, ${formatPercent(entry.node.p_reach)} chance of being reached`}
                    </title>
                  </g>
                );
              })}

              {row.overflowX !== null && (
                <g className="blast-tree__overflow">
                  <line
                    x1={row.overflowX}
                    y1={row.railY}
                    x2={row.overflowX}
                    y2={row.railY + RAIL_DROP - NODE_RADIUS - 4}
                    className="blast-tree__rail"
                  />
                  <circle
                    cx={row.overflowX}
                    cy={row.railY + RAIL_DROP}
                    r={NODE_RADIUS}
                    className="blast-tree__overflow-circle"
                  />
                  <text
                    x={row.overflowX}
                    y={row.railY + RAIL_DROP + 4}
                    textAnchor="middle"
                    className="blast-tree__overflow-count"
                  >
                    +{row.hidden}
                  </text>
                  <text
                    x={row.overflowX}
                    y={row.railY + RAIL_DROP + NODE_RADIUS + 17}
                    textAnchor="middle"
                    className="blast-tree__node-label"
                  >
                    more
                  </text>
                  <title>
                    {`${row.hidden} more thing${row.hidden === 1 ? '' : 's'} ${row.depth} ${row.depth === 1 ? 'step' : 'steps'} away, all less likely to be reached than the ones drawn. They are in the full list below.`}
                  </title>
                </g>
              )}
            </g>
          ))}

          {/* The origin last, so it paints over the top of the trunk. */}
          <g>
            <circle
              cx={centreX}
              cy={ORIGIN_Y}
              r={ORIGIN_RADIUS + 6}
              className="blast-tree__origin-halo"
            />
            <circle
              cx={centreX}
              cy={ORIGIN_Y}
              r={ORIGIN_RADIUS}
              className="blast-tree__circle"
              fill={originKind ? originKind.ui_color : 'var(--text-muted)'}
              stroke={isTruthy(origin?.is_crown_jewel ?? 0) ? CROWN_STROKE : 'var(--bg-card)'}
              strokeWidth={isTruthy(origin?.is_crown_jewel ?? 0) ? 3 : 2}
            />
            <text
              x={centreX}
              y={ORIGIN_Y - ORIGIN_RADIUS - 10}
              textAnchor="middle"
              className="blast-tree__origin-label"
            >
              {truncate(originName, 22)}
            </text>
            <title>{`${originName} — the node assumed to be compromised`}</title>
          </g>
        </svg>
      </div>

      <ul className="blast-tree__legend">
        {kindsPresent.length > 0 && (
          <li className="blast-tree__legend-group">
            {kindsPresent.map((kind) => (
              <span key={kind.code} className="blast-tree__legend-item">
                <Icon name={kind.ui_icon ?? 'circle'} style={{ color: nodeColorVar(kind.code) }} />
                {kind.label}
              </span>
            ))}
          </li>
        )}
        {tiers.length > 0 && (
          <li className="blast-tree__legend-group blast-tree__legend-group--risk">
            {[...tiers]
              .sort((a, b) => a.sort_order - b.sort_order)
              .map((tier) => (
                <span key={tier.code} className="blast-tree__legend-item">
                  <span className="blast-tree__legend-swatch" style={{ background: tier.ui_color }} />
                  {tier.label}
                </span>
              ))}
          </li>
        )}
      </ul>

      {selected ? (
        <div className="blast-tree__detail" role="status">
          <span className="blast-tree__detail-kind">{selected.kind ?? '—'}</span>
          <span className="blast-tree__detail-name" title={selected.node_id}>
            {selected.name}
            {isTruthy(selected.is_crown_jewel) && <Icon name="crown" className="blast-tree__detail-crown" />}
          </span>
          <span className="blast-tree__detail-fact">
            {selected.depth} {selected.depth === 1 ? 'step' : 'steps'} away
          </span>
          <span className="blast-tree__detail-fact">
            {formatPercent(selected.p_reach)} chance of being reached
          </span>
          {selectedTier && <RiskTierBadge code={selectedTier} size="sm" />}
          <span className="blast-tree__detail-id">{shortId(selected.node_id, 24)}</span>
        </div>
      ) : (
        <p className="blast-tree__detail blast-tree__detail--empty">
          Click any circle for its exact numbers.
        </p>
      )}
    </div>
  );
}
