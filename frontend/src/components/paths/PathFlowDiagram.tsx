import { useRiskTierConfigs, tierCodeForScore } from '@/api/config';
import type { PathHop, PathNode } from '@/api/types';
import { Icon } from '@/components/ui/Icon';
import { riskBgVar, riskColorVar } from '@/theme/applyRuntimeTheme';
import { formatPercent, shortId } from '@/lib/format';
import './PathFlowDiagram.css';

interface PathFlowDiagramProps {
  hops: PathHop[];
  nodeLabel: (nodeId: string) => PathNode | undefined;
  targetIsCrownJewel: boolean;
  selectedHopNo: number;
  onSelectHop: (hopNo: number) => void;
}

function labelFor(nodeId: string, lookup: (nodeId: string) => PathNode | undefined): string {
  const node = lookup(nodeId);
  return node?.display_name || node?.name || shortId(nodeId);
}

/**
 * The whole attack path as one chain: every node it passes through, connected
 * by the transition that got the attacker from one to the next -- all hops
 * visible together, coloured by how easy each one is for an attacker, so the
 * highs and lows read at a glance without clicking anything.
 *
 * Colour reuses the exact same risk-tier bands and colours as the path-level
 * RiskTierBadge (mapping each step's own success chance onto the 0-10 scale
 * those bands are defined on), rather than a second colour scale invented
 * just for this diagram -- one fewer thing to learn, and it can never drift
 * out of sync with what "red" means everywhere else in the app.
 *
 * Clicking a transition selects it, and the caller renders that one hop's
 * full detail below -- so a six-hop path is one diagram plus one detail
 * panel, never six full cards stacked on top of each other.
 */
export function PathFlowDiagram({
  hops,
  nodeLabel,
  targetIsCrownJewel,
  selectedHopNo,
  onSelectHop,
}: PathFlowDiagramProps) {
  const { data: tiers = [] } = useRiskTierConfigs();

  const firstHop = hops[0];
  if (!firstHop) return null;

  const nodeIds = [firstHop.src_node_id, ...hops.map((hop) => hop.dst_node_id)];

  return (
    <div className="path-flow" role="list" aria-label="Attack path, node by node">
      {nodeIds.map((nodeId, i) => {
        const isLast = i === nodeIds.length - 1;
        const hop = hops[i];
        const tierCode = hop ? tierCodeForScore(hop.p_succ * 10, tiers) : undefined;

        return (
          <div className="path-flow__segment" key={`${nodeId}-${i}`}>
            <div className="path-flow__node" role="listitem" title={nodeId}>
              <span className="path-flow__node-label">{labelFor(nodeId, nodeLabel)}</span>
              {isLast && targetIsCrownJewel && (
                <Icon name="crown" className="path-flow__node-crown" />
              )}
            </div>

            {!isLast && hop && (
              <button
                type="button"
                className={`path-flow__transition${hop.hop_no === selectedHopNo ? ' path-flow__transition--active' : ''}`}
                onClick={() => onSelectHop(hop.hop_no)}
                aria-pressed={hop.hop_no === selectedHopNo}
                style={
                  tierCode
                    ? { borderTopColor: riskColorVar(tierCode), background: riskBgVar(tierCode) }
                    : undefined
                }
                title={`${hop.technique_name} -- ${formatPercent(hop.p_succ)} chance this step works`}
              >
                <span
                  className="path-flow__transition-line"
                  aria-hidden="true"
                  style={tierCode ? { color: riskColorVar(tierCode) } : undefined}
                >
                  <Icon name="arrow-narrow-right" />
                </span>
                <span className="path-flow__transition-label">
                  {hop.technique_name}
                  <span
                    className="path-flow__transition-prob"
                    style={tierCode ? { color: riskColorVar(tierCode) } : undefined}
                  >
                    {formatPercent(hop.p_succ)}
                  </span>
                </span>
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}
