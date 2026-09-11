import type { GraphStats, GraphVersion } from '@/api/graph';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { StatCard } from '@/components/dashboard/StatCard';
import { nodeColorVar } from '@/theme/applyRuntimeTheme';
import { formatCount } from '@/lib/format';
import './GraphStatsHeader.css';

interface GraphStatsHeaderProps {
  version: GraphVersion;
  stats: GraphStats;
}

/** Version metadata plus the node/edge/crown-jewel counts, with a by-kind breakdown underneath. */
export function GraphStatsHeader({ version, stats }: GraphStatsHeaderProps) {
  const kindEntries = Object.entries(stats.by_kind).sort((a, b) => b[1] - a[1]);
  const edgeEntries = Object.entries(stats.by_edge_type).sort((a, b) => b[1] - a[1]);

  return (
    <div className="graph-stats-header">
      <div className="graph-stats-header__stats">
        <StatCard icon="topology-star-3" label="Nodes" value={formatCount(stats.node_count)} accent="cyan" delay={0} />
        <StatCard icon="git-merge" label="Edges" value={formatCount(stats.edge_count)} accent="purple" delay={0.04} />
        <StatCard icon="crown" label="Crown jewels" value={formatCount(stats.crown_jewels)} accent="amber" delay={0.08} />
        <StatCard
          icon="database"
          label="Graph version"
          value={`#${version.id}`}
          sublabel={`${version.label} · seed ${version.seed ?? '—'}`}
          accent="emerald"
          delay={0.12}
        />
      </div>

      <GlassPanel padding="md" className="graph-stats-header__breakdown">
        <div className="graph-stats-header__breakdown-group">
          <span className="graph-stats-header__breakdown-title">Nodes by kind</span>
          <div className="graph-stats-header__chips">
            {kindEntries.map(([kind, count]) => (
              <span key={kind} className="graph-stats-header__chip">
                <span className="graph-stats-header__chip-dot" style={{ background: nodeColorVar(kind) }} />
                {kind}
                <span className="graph-stats-header__chip-count">{formatCount(count)}</span>
              </span>
            ))}
          </div>
        </div>
        <div className="graph-stats-header__breakdown-group">
          <span className="graph-stats-header__breakdown-title">Edges by type</span>
          <div className="graph-stats-header__chips">
            {edgeEntries.map(([edgeType, count]) => (
              <span key={edgeType} className="graph-stats-header__chip">
                {edgeType}
                <span className="graph-stats-header__chip-count">{formatCount(count)}</span>
              </span>
            ))}
          </div>
        </div>
      </GlassPanel>
    </div>
  );
}
