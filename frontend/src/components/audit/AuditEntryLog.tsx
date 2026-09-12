import { Fragment, useState } from 'react';

import { ApiError } from '@/api/client';
import { useAuditActions, useAuditEntries } from '@/api/audit';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, shortId } from '@/lib/format';
import './AuditEntryLog.css';

const PAGE_SIZE = 20;

function formatDate(value: string): string {
  const parsed = new Date(value.endsWith('Z') ? value : `${value}Z`);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

/** The paginated, filterable entry log -- one table with a single shared legend for what the
 * colour dot means, rather than repeating an explanation per row (docs/SCOPE.md D13). */
export function AuditEntryLog() {
  const [actionCode, setActionCode] = useState('');
  const [actorInput, setActorInput] = useState('');
  const [offset, setOffset] = useState(0);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);

  const actions = useAuditActions();
  const entries = useAuditEntries({
    actionCode: actionCode || undefined,
    actor: actorInput || undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const actionByCode = new Map((actions.data ?? []).map((a) => [a.code, a]));

  const handleActionChange = (value: string) => {
    setActionCode(value);
    setOffset(0);
  };

  return (
    <GlassPanel padding="lg" className="audit-log">
      <div className="audit-log__header">
        <Icon name="list-details" className="audit-log__icon" />
        <div>
          <h2 className="audit-log__title">Entry log</h2>
          <p className="audit-log__intro">
            Every recorded action, oldest position (<code>seq</code>) never reused, reordered or
            deleted. The salt beside each entry is what makes selective disclosure possible: a
            proof can confirm one entry without exposing the content of any other.
          </p>
        </div>
        {entries.data && (
          <span className="audit-log__count">
            {formatCount(entries.data.items.length)}
            {entries.data.total !== entries.data.items.length ? ` of ${formatCount(entries.data.total)}` : ''} entries
          </span>
        )}
      </div>

      <div className="audit-log__filters">
        <select value={actionCode} onChange={(event) => handleActionChange(event.target.value)}>
          <option value="">All actions</option>
          {(actions.data ?? []).map((a) => (
            <option key={a.code} value={a.code}>
              {a.label}
            </option>
          ))}
        </select>
        <label className="audit-log__search">
          <Icon name="search" />
          <input
            type="text"
            placeholder="Filter by actor…"
            value={actorInput}
            onChange={(event) => {
              setActorInput(event.target.value);
              setOffset(0);
            }}
          />
        </label>
      </div>

      {entries.isLoading && <LoadingState variant="list" rows={6} />}

      {entries.isError && (
        <ErrorState
          message={
            entries.error instanceof ApiError ? entries.error.message : 'Could not load the entry log.'
          }
        />
      )}

      {entries.data && entries.data.total === 0 && (
        <EmptyState
          icon="list-details"
          title="Nothing has been logged yet"
          description="Entries appear here as soon as an action that faultline records (a discovery run, a fix applied, a checkpoint anchored) happens."
        />
      )}

      {entries.data && entries.data.items.length === 0 && entries.data.total > 0 && (
        <p className="audit-log__empty-filtered">No entries match these filters.</p>
      )}

      {entries.data && entries.data.items.length > 0 && (
        <>
          <div className="audit-log__table-scroll">
            <table className="audit-log__table">
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Target</th>
                  <th>Risk Δ</th>
                  <th>Recorded</th>
                  <th aria-label="proof" />
                </tr>
              </thead>
              <tbody>
                {entries.data.items.map((entry) => {
                  const action = actionByCode.get(entry.action_code);
                  const expanded = expandedSeq === entry.seq;
                  return (
                    <Fragment key={entry.seq}>
                      <tr>
                        <td className="audit-log__number">#{entry.seq}</td>
                        <td>
                          <span
                            className="audit-log__action-dot"
                            style={{ background: action?.ui_color ?? 'var(--text-muted)' }}
                          />
                          {action?.label ?? entry.action_code}
                        </td>
                        <td className="audit-log__actor">{entry.actor}</td>
                        <td>
                          {entry.target_kind ? (
                            <span title={entry.target_id ?? undefined}>
                              {entry.target_kind}
                              {entry.target_id ? ` · ${shortId(entry.target_id, 10)}` : ''}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="audit-log__risk">
                          {entry.risk_before !== null && entry.risk_after !== null
                            ? `${entry.risk_before.toFixed(2)} → ${entry.risk_after.toFixed(2)}`
                            : '—'}
                        </td>
                        <td className="audit-log__date">{formatDate(entry.created_at)}</td>
                        <td>
                          <button
                            type="button"
                            className="audit-log__expand"
                            onClick={() => setExpandedSeq(expanded ? null : entry.seq)}
                            aria-label={expanded ? 'Hide proof material' : 'Show proof material'}
                          >
                            <Icon name={expanded ? 'chevron-up' : 'chevron-down'} />
                          </button>
                        </td>
                      </tr>
                      {expanded && (
                        <tr className="audit-log__detail-row" key={`${entry.seq}-detail`}>
                          <td colSpan={7}>
                            <dl className="audit-log__proof-detail">
                              <div>
                                <dt>Leaf hash</dt>
                                <dd className="audit-log__mono">{entry.leaf_hash_hex}</dd>
                              </div>
                              <div>
                                <dt>Salt (released here, alongside this proof, and nowhere else)</dt>
                                <dd className="audit-log__mono">{entry.salt_hex}</dd>
                              </div>
                              <div>
                                <dt>Chain link (entry_hash)</dt>
                                <dd className="audit-log__mono">{entry.entry_hash_hex}</dd>
                              </div>
                              <div>
                                <dt>Payload</dt>
                                <dd>
                                  <pre className="audit-log__payload">{JSON.stringify(entry.payload, null, 2)}</pre>
                                </dd>
                              </div>
                            </dl>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="audit-log__legend">
            The coloured dot marks which action produced the entry (colours come from the action
            catalogue, not invented here); a solid outline in the catalogue means the action
            mutates state rather than only reading it. Expand a row to see its leaf hash and salt
            -- releasing a salt alongside its entry is what proves that one entry without exposing
            any other.
          </p>

          <div className="audit-log__pagination">
            <button
              type="button"
              className="pill-button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              Previous
            </button>
            <span className="audit-log__page-label">
              {offset + 1}–{Math.min(offset + PAGE_SIZE, entries.data.total)} of {formatCount(entries.data.total)}
            </span>
            <button
              type="button"
              className="pill-button"
              disabled={offset + PAGE_SIZE >= entries.data.total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </GlassPanel>
  );
}
