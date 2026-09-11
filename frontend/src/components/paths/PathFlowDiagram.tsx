import { useRiskTierConfigs, useVocabularies, tierCodeForScore } from '@/api/config';
import type { PathHop, PathNode } from '@/api/types';
import { Icon } from '@/components/ui/Icon';
import { nodeColorVar } from '@/theme/applyRuntimeTheme';
import { formatPercent, shortId } from '@/lib/format';
import './PathFlowDiagram.css';

interface PathFlowDiagramProps {
  hops: PathHop[];
  nodeLabel: (nodeId: string) => PathNode | undefined;
  targetIsCrownJewel: boolean;
  selectedHopNo: number;
  onSelectHop: (hopNo: number) => void;
}

const NODE_SPACING = 190;
const NODE_RADIUS = 22;
const DIAGRAM_HEIGHT = 150;
const NODE_Y = 62;
// Wide enough that a ~14-character node label, centred on the first or last
// node, never clips against the SVG's own edge -- text-anchor="middle" on a
// long label extends well past the circle it's centred on in both
// directions, and the first/last node have no neighbouring label to borrow
// margin from.
const MARGIN_X = 70;

function labelFor(nodeId: string, lookup: (nodeId: string) => PathNode | undefined): string {
  const node = lookup(nodeId);
  return node?.display_name || node?.name || shortId(nodeId);
}

function truncate(text: string, max = 14): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * The whole attack path as one node-and-edge graph: every asset it passes
 * through drawn as a node, connected by the technique that got the attacker
 * from one to the next -- the same visual language as the Graph Explorer's
 * node colouring (by asset kind), so a path reads as a small piece of the
 * real graph rather than an abstract flow chart or bar chart.
 *
 * Edges carry the risk colour instead: each one tinted by how easy that
 * specific step is for an attacker, using the exact same risk-tier bands and
 * colours as the path-level RiskTierBadge (the step's own success chance
 * mapped onto the 0-10 scale those bands are defined on) -- one colour
 * scale, reused everywhere it means the same thing, rather than inventing a
 * second one for this one diagram.
 *
 * All hops render together so the highs and lows are visible without
 * clicking anything; clicking an edge selects it, and the caller renders
 * that one hop's full detail below -- one diagram plus one detail panel,
 * never one full card per hop.
 */
export function PathFlowDiagram({
  hops,
  nodeLabel,
  targetIsCrownJewel,
  selectedHopNo,
  onSelectHop,
}: PathFlowDiagramProps) {
  const { data: tiers = [] } = useRiskTierConfigs();
  const { data: vocab } = useVocabularies();
  const nodeKindByCode = new Map((vocab?.node_kinds ?? []).map((k) => [k.code, k]));

  const firstHop = hops[0];
  if (!firstHop) return null;

  const nodeIds = [firstHop.src_node_id, ...hops.map((hop) => hop.dst_node_id)];
  const width = NODE_SPACING * (nodeIds.length - 1) + MARGIN_X * 2;

  return (
    <div className="path-flow">
      <div className="path-flow__scroll">
        <svg
          className="path-flow__svg"
          width={width}
          height={DIAGRAM_HEIGHT}
          viewBox={`0 0 ${width} ${DIAGRAM_HEIGHT}`}
          role="img"
          aria-label="Attack path diagram: nodes and the techniques connecting them"
        >
          <defs>
            {tiers.map((tier) => (
              <marker
                key={tier.code}
                id={`path-flow-arrow-${tier.code}`}
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M0,0 L10,5 L0,10 z" fill={tier.ui_color} />
              </marker>
            ))}
          </defs>

          {/* Edges drawn first so node circles paint on top of the line ends. */}
          {hops.map((hop, i) => {
            const x1 = MARGIN_X + i * NODE_SPACING;
            const x2 = MARGIN_X + (i + 1) * NODE_SPACING;
            const tierCode = tierCodeForScore(hop.p_succ * 10, tiers);
            const tier = tiers.find((t) => t.code === tierCode);
            const isActive = hop.hop_no === selectedHopNo;
            const strokeColor = tier?.ui_color ?? 'var(--text-muted)';

            return (
              <g
                key={hop.hop_no}
                className={`path-flow__edge${isActive ? ' path-flow__edge--active' : ''}`}
                role="button"
                tabIndex={0}
                aria-pressed={isActive}
                onClick={() => onSelectHop(hop.hop_no)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') onSelectHop(hop.hop_no);
                }}
              >
                {/* Wide invisible hit area -- the visible line is thin, but the click/tap target should not be. */}
                <line x1={x1} y1={NODE_Y} x2={x2} y2={NODE_Y} className="path-flow__edge-hit" />
                <line
                  x1={x1}
                  y1={NODE_Y}
                  x2={x2}
                  y2={NODE_Y}
                  className="path-flow__edge-line"
                  stroke={strokeColor}
                  strokeWidth={isActive ? 4 : 2.5}
                  markerEnd={tierCode ? `url(#path-flow-arrow-${tierCode})` : undefined}
                />
                <text x={(x1 + x2) / 2} y={NODE_Y - 16} className="path-flow__edge-label" textAnchor="middle">
                  {truncate(hop.technique_name, 20)}
                </text>
                <text
                  x={(x1 + x2) / 2}
                  y={NODE_Y + 26}
                  className="path-flow__edge-prob"
                  textAnchor="middle"
                  fill={strokeColor}
                >
                  {formatPercent(hop.p_succ)}
                </text>
              </g>
            );
          })}

          {nodeIds.map((nodeId, i) => {
            const isLast = i === nodeIds.length - 1;
            const node = nodeLabel(nodeId);
            const kind = node ? nodeKindByCode.get(node.kind_code) : undefined;
            const cx = MARGIN_X + i * NODE_SPACING;
            const fill = kind ? kind.ui_color : 'var(--text-muted)';

            return (
              <g key={`${nodeId}-${i}`}>
                <circle
                  cx={cx}
                  cy={NODE_Y}
                  r={NODE_RADIUS}
                  className="path-flow__node-circle"
                  fill={fill}
                  stroke={isLast && targetIsCrownJewel ? '#d97706' : 'var(--bg-card)'}
                  strokeWidth={isLast && targetIsCrownJewel ? 3 : 2}
                />
                {isLast && targetIsCrownJewel && (
                  <text x={cx} y={NODE_Y + 5} textAnchor="middle" className="path-flow__node-crown" aria-label="crown jewel">
                    ♛
                  </text>
                )}
                <text x={cx} y={NODE_Y + NODE_RADIUS + 20} textAnchor="middle" className="path-flow__node-label">
                  {truncate(labelFor(nodeId, nodeLabel))}
                </text>
                <title>{node?.display_name || node?.name || nodeId}</title>
              </g>
            );
          })}
        </svg>
      </div>

      <ul className="path-flow__legend" aria-hidden="true">
        {(vocab?.node_kinds ?? []).length > 0 && (
          <li className="path-flow__legend-group">
            {(vocab?.node_kinds ?? [])
              .filter((k) => nodeIds.some((id) => nodeLabel(id)?.kind_code === k.code))
              .map((k) => (
                <span key={k.code} className="path-flow__legend-item">
                  <Icon name={k.ui_icon ?? 'circle'} style={{ color: nodeColorVar(k.code) }} />
                  {k.label}
                </span>
              ))}
          </li>
        )}
      </ul>
    </div>
  );
}
