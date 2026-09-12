import { useVerificationHistory } from '@/api/audit';
import { ChainStatusPanel } from '@/components/audit/ChainStatusPanel';
import { CheckpointHistoryTable } from '@/components/audit/CheckpointHistoryTable';
import { AuditEntryLog } from '@/components/audit/AuditEntryLog';
import './AuditTrail.css';

/**
 * The tamper-evident record: chain status (with a real red path, not only a
 * self-check -- docs/SCOPE.md D7), checkpoint/anchor history, and the
 * paginated entry log. Each panel manages its own loading/error/empty state
 * against real data; there is no page-level fetch to gate on here.
 */
export function AuditTrail() {
  const history = useVerificationHistory(1);
  const latest = history.data?.[0];

  return (
    <div className="audit-trail">
      <ChainStatusPanel report={latest} isLoading={history.isLoading} error={history.error} />
      <CheckpointHistoryTable />
      <AuditEntryLog />
    </div>
  );
}
