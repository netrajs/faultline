import { useState } from 'react';

import { ApiError } from '@/api/client';
import type { AnchorMode } from '@/api/audit';
import { useCheckpoints, useRunAnchor } from '@/api/audit';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, shortId } from '@/lib/format';
import './CheckpointHistoryTable.css';

const MODE_OPTIONS: { value: AnchorMode; label: string }[] = [
  { value: 'replay', label: 'Replay (recorded)' },
  { value: 'anvil', label: 'Anvil (local chain)' },
  { value: 'base-sepolia', label: 'Base Sepolia' },
  { value: 'polygon-amoy', label: 'Polygon Amoy' },
];

function formatDate(value: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value.endsWith('Z') ? value : `${value}Z`);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

/** One row per anchor attempt, on one comparative table rather than one card per checkpoint
 * (docs/SCOPE.md D13) -- a checkpoint anchored on two chains, or retried after a failed live
 * attempt, shows as multiple rows sharing the same epoch. */
export function CheckpointHistoryTable() {
  const [mode, setMode] = useState<AnchorMode>('replay');
  const checkpoints = useCheckpoints();
  const runAnchor = useRunAnchor();

  return (
    <GlassPanel padding="lg" className="checkpoint-history">
      <div className="checkpoint-history__header">
        <Icon name="link" className="checkpoint-history__icon" />
        <div>
          <h2 className="checkpoint-history__title">Checkpoints and anchors</h2>
          <p className="checkpoint-history__intro">
            A checkpoint publishes a Merkle root over the log as of a given size, outside this
            database. <strong>Recorded</strong> receipts replay a previously saved anchoring
            session (see the anchor mode legend below) rather than calling a live chain right now
            -- that is a deliberate, always-available fallback, not a placeholder pretending to be
            real. <strong>Confirmed</strong> would mean a real transaction was just sent and mined.
          </p>
        </div>
        <div className="checkpoint-history__controls">
          <select value={mode} onChange={(event) => setMode(event.target.value as AnchorMode)} disabled={runAnchor.isPending}>
            {MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="pill-button pill-button--primary"
            onClick={() => runAnchor.mutate(mode)}
            disabled={runAnchor.isPending}
          >
            <Icon name={runAnchor.isPending ? 'loader-2' : 'stamp'} className={runAnchor.isPending ? 'settings-spin' : ''} />
            {runAnchor.isPending ? 'Anchoring…' : 'Publish checkpoint'}
          </button>
        </div>
      </div>

      {runAnchor.isError && (
        <ErrorState
          title={runAnchor.error instanceof ApiError && runAnchor.error.status === 501 ? 'Live anchoring unavailable' : 'Anchoring failed'}
          message={
            runAnchor.error instanceof ApiError
              ? runAnchor.error.message
              : 'Could not reach the API to publish a checkpoint.'
          }
        />
      )}

      {checkpoints.isLoading && <LoadingState variant="list" rows={4} />}

      {checkpoints.isError && (
        <ErrorState
          message={
            checkpoints.error instanceof ApiError
              ? checkpoints.error.message
              : 'Could not load checkpoint history.'
          }
        />
      )}

      {checkpoints.data && checkpoints.data.items.length === 0 && (
        <EmptyState
          icon="link"
          title="No checkpoints published yet"
          description="Log at least one entry, then publish a checkpoint to anchor the log outside this database."
        />
      )}

      {checkpoints.data && checkpoints.data.items.length > 0 && (
        <>
          <div className="checkpoint-history__table-scroll">
            <table className="checkpoint-history__table">
              <thead>
                <tr>
                  <th>Epoch</th>
                  <th>Tree size</th>
                  <th>Root</th>
                  <th>Published</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Tx / reference</th>
                </tr>
              </thead>
              <tbody>
                {checkpoints.data.items.flatMap((checkpoint) =>
                  (checkpoint.receipts.length > 0 ? checkpoint.receipts : [null]).map((receipt, idx) => (
                    <tr key={`${checkpoint.epoch}-${receipt?.id ?? idx}`}>
                      {idx === 0 && (
                        <>
                          <td rowSpan={checkpoint.receipts.length || 1} className="checkpoint-history__epoch">
                            #{checkpoint.epoch}
                          </td>
                          <td rowSpan={checkpoint.receipts.length || 1} className="checkpoint-history__number">
                            {formatCount(checkpoint.tree_size)}
                          </td>
                          <td rowSpan={checkpoint.receipts.length || 1} className="checkpoint-history__mono" title={checkpoint.root_hex}>
                            {shortId(checkpoint.root_hex, 8)}
                          </td>
                          <td rowSpan={checkpoint.receipts.length || 1}>{formatDate(checkpoint.created_at)}</td>
                        </>
                      )}
                      {receipt ? (
                        <>
                          <td>
                            <span className="checkpoint-history__mode">{receipt.mode}</span>
                          </td>
                          <td>
                            <span className={`checkpoint-history__status checkpoint-history__status--${receipt.status}`}>
                              {receipt.status === 'recorded' ? 'Recorded (not live)' : receipt.status}
                            </span>
                          </td>
                          <td className="checkpoint-history__mono">
                            {receipt.explorer_url && receipt.status !== 'recorded' ? (
                              <a href={receipt.explorer_url} target="_blank" rel="noreferrer">
                                {shortId(receipt.tx_hash ?? '', 6)} <Icon name="external-link" />
                              </a>
                            ) : (
                              <span title={receipt.explorer_url ?? undefined}>{shortId(receipt.tx_hash ?? '—', 6)}</span>
                            )}
                          </td>
                        </>
                      ) : (
                        <td colSpan={3} className="checkpoint-history__no-receipt">
                          No anchor receipt recorded for this checkpoint.
                        </td>
                      )}
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
          <p className="checkpoint-history__legend">
            <strong>Recorded</strong> = served from a fixture of previously anchored sessions, no
            live chain call was made just now. <strong>Confirmed</strong> = a real transaction was
            sent and mined. <strong>Pending</strong> = sent but not yet confirmed.{' '}
            <strong>Failed</strong> = the attempt did not go through.
          </p>
        </>
      )}
    </GlassPanel>
  );
}
