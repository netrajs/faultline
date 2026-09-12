import type { DependencySeverity, RecommendationDependency } from '@/api/remediation';
import { Icon } from '@/components/ui/Icon';
import './DependencyPanel.css';

const SEVERITY_ORDER: DependencySeverity[] = ['blocking', 'warning', 'info'];

const SEVERITY_ICON: Record<DependencySeverity, string> = {
  blocking: 'alert-octagon',
  warning: 'alert-triangle',
  info: 'info-circle',
};

const SEVERITY_LABEL: Record<DependencySeverity, string> = {
  blocking: 'Blocking',
  warning: 'Warning',
  info: 'Note',
};

const KIND_LABEL: Record<string, string> = {
  access_lost: 'Access lost',
  shared_credential: 'Shared credential',
  downstream_service: 'Downstream service',
  policy_conflict: 'Policy conflict',
};

/**
 * What else this fix breaks, as far as the graph can actually show it.
 *
 * Every row traces to edges that are in the graph -- other principals holding
 * the credential being revoked, the permissions a group membership was
 * conferring, the assets a credential authenticates to. Nothing here is a
 * guess at an organisation's operational reality, which is why a fix with
 * nothing derivable shows an explicit "nothing derivable" rather than a
 * plausible warning nobody can check.
 */
export function DependencyPanel({ dependencies }: { dependencies: RecommendationDependency[] }) {
  if (dependencies.length === 0) {
    return (
      <p className="dependency-panel__none">
        The graph shows no collateral for this change. That is not a promise that nothing breaks
        &mdash; it means nothing in the recorded relationships depends on what this fix touches, and
        inventing a warning here would be a guess dressed as a finding.
      </p>
    );
  }

  const sorted = [...dependencies].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.seq - b.seq,
  );

  return (
    <div className="dependency-panel">
      <ul className="dependency-panel__list">
        {sorted.map((dependency) => (
          <li key={dependency.seq} className={`dependency-panel__row dependency-panel__row--${dependency.severity}`}>
            <Icon name={SEVERITY_ICON[dependency.severity] ?? 'info-circle'} className="dependency-panel__icon" />
            <div className="dependency-panel__body">
              <span className="dependency-panel__tags">
                <span className="dependency-panel__severity">{SEVERITY_LABEL[dependency.severity] ?? dependency.severity}</span>
                <span className="dependency-panel__kind">{KIND_LABEL[dependency.kind] ?? dependency.kind}</span>
                {dependency.affected_node_id && (
                  <span className="dependency-panel__node" title={dependency.affected_node_id}>
                    {dependency.affected_node_id}
                  </span>
                )}
              </span>
              <p className="dependency-panel__description">{dependency.description}</p>
            </div>
          </li>
        ))}
      </ul>
      <p className="dependency-panel__legend">
        <strong>Blocking</strong> means applying this as written would take something down &mdash;
        an account with no other way to authenticate, a non-interactive identity with nobody present
        to produce a hardware factor. <strong>Warning</strong> means real access is lost and somebody
        has to be told. <strong>Note</strong> is context.
      </p>
    </div>
  );
}
