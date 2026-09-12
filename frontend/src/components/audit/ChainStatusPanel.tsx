import { ApiError } from '@/api/client';
import type { VerificationReport } from '@/api/audit';
import { useRunVerification } from '@/api/audit';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { ErrorState } from '@/components/ui/StateViews';
import './ChainStatusPanel.css';

function formatWindow(seconds: number): string {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    const remSeconds = seconds % 60;
    return `${minutes} minute${minutes === 1 ? '' : 's'}${remSeconds ? ` ${remSeconds}s` : ''}`;
  }
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return `${hours} hour${hours === 1 ? '' : 's'}${remMinutes ? ` ${remMinutes}m` : ''}`;
}

function formatCheckedAt(value: string): string {
  const parsed = new Date(value.endsWith('Z') ? value : `${value}Z`);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

interface ProofBadgeProps {
  label: string;
  ok: boolean | null;
}

function ProofBadge({ label, ok }: ProofBadgeProps) {
  const state = ok === null ? 'unknown' : ok ? 'ok' : 'fail';
  const icon = state === 'ok' ? 'circle-check' : state === 'fail' ? 'circle-x' : 'minus';
  return (
    <span className={`chain-status__proof chain-status__proof--${state}`}>
      <Icon name={icon} />
      {label}
    </span>
  );
}

interface ChainStatusPanelProps {
  report: VerificationReport | undefined;
  isLoading: boolean;
  error: unknown;
}

/** The chain-status panel: intact/tampered, the tamper window stated in plain language, and a
 * visible action to run verification for real -- see docs/SCOPE.md D7 on why this has to be able
 * to render red rather than only ever confirming itself. */
export function ChainStatusPanel({ report, isLoading, error }: ChainStatusPanelProps) {
  const runVerification = useRunVerification();

  const displayed = runVerification.data ?? report;
  const busy = runVerification.isPending || isLoading;

  return (
    <GlassPanel padding="lg" raised className="chain-status">
      <div className="chain-status__header">
        <Icon name="shield-lock" className="chain-status__icon" />
        <div>
          <h2 className="chain-status__title">Chain status</h2>
          <p className="chain-status__intro">
            Every recorded action is chained by hash to the one before it, and the chain is
            periodically anchored outside this database (see the checkpoint history below). A
            hash chain that only checks itself proves little on its own -- an attacker with
            database access could recompute it end to end -- so this panel reports two things
            separately: whether the local chain is self-consistent, and how far that
            self-consistency check can actually be trusted right now.
          </p>
        </div>
        <button
          type="button"
          className="pill-button pill-button--primary chain-status__run"
          onClick={() => runVerification.mutate()}
          disabled={busy}
        >
          <Icon name={runVerification.isPending ? 'loader-2' : 'refresh'} className={runVerification.isPending ? 'settings-spin' : ''} />
          {runVerification.isPending ? 'Verifying…' : 'Run verification'}
        </button>
      </div>

      {isLoading && !displayed && <p className="chain-status__empty">Loading the last verification result…</p>}

      {Boolean(error) && !displayed && (
        <ErrorState
          message={error instanceof ApiError ? error.message : 'Could not load verification history.'}
        />
      )}

      {runVerification.isError && (
        <ErrorState
          title="Verification could not run"
          message={
            runVerification.error instanceof ApiError
              ? runVerification.error.message
              : 'Could not reach the API to run verification.'
          }
        />
      )}

      {!isLoading && !error && !displayed && (
        <p className="chain-status__empty">
          Nothing has been verified yet. Log at least one entry, then run verification.
        </p>
      )}

      {displayed && (
        <>
          <div className={`chain-status__badge chain-status__badge--${displayed.chain_intact ? 'intact' : 'tampered'}`}>
            <Icon name={displayed.chain_intact ? 'shield-check' : 'alert-triangle'} />
            <span>
              {displayed.chain_intact
                ? `Chain intact across ${displayed.entries_checked.toLocaleString()} entries`
                : `Tampering detected at entry #${displayed.first_divergent_seq}`}
            </span>
          </div>

          {displayed.tamper_window_seconds !== null ? (
            <p className="chain-status__window">
              Last anchored {formatWindow(displayed.tamper_window_seconds)} ago
              {displayed.anchor_epoch !== null ? ` (checkpoint #${displayed.anchor_epoch})` : ''}. In plain terms: an
              attacker with database write access could have altered anything committed in the
              last {formatWindow(displayed.tamper_window_seconds)} without this check being able to
              tell -- everything committed before that anchor cannot be changed without the
              anchor comparison below failing.
            </p>
          ) : (
            <p className="chain-status__window chain-status__window--unanchored">
              No checkpoint has been anchored yet, so the entire log is currently in the tamper
              window -- a database-level rewrite would pass this chain check today. Anchor a
              checkpoint below to shrink that window.
            </p>
          )}

          <div className="chain-status__proofs">
            <ProofBadge label="Anchor root matches" ok={displayed.anchor_matched} />
            <ProofBadge label="Inclusion proof" ok={displayed.inclusion_proof_ok} />
            <ProofBadge label="Consistency proof" ok={displayed.consistency_proof_ok} />
          </div>
          <p className="chain-status__legend">
            <strong>Anchor root matches</strong> recomputes the Merkle root from today's entries and
            checks it against the root published outside this database -- the check a full
            rewrite cannot fake. <strong>Inclusion proof</strong> proves one specific recent entry
            is really part of that anchored root. <strong>Consistency proof</strong> proves the
            previous anchor's log is a strict prefix of this one, i.e. history was extended, not
            replaced. A dash means there is not yet enough anchor history to run that check.
          </p>

          <p className="chain-status__checked-at">Last checked {formatCheckedAt(displayed.checked_at)}.</p>
        </>
      )}
    </GlassPanel>
  );
}
