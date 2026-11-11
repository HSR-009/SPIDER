interface ProgressStripProps {
  stage?: string;
  done?: number;
  total?: number;
}

export function ProgressStrip({ stage, done, total }: ProgressStripProps) {
  const percent = total && total > 0 && done !== undefined ? Math.round((done / total) * 100) : null;

  return (
    <div
      role="status"
      style={{
        background: 'var(--color-surface-sunken)',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-sm)',
        padding: 'var(--space-3)',
        marginTop: 'var(--space-3)',
        marginBottom: 'var(--space-4)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', marginBottom: '4px' }}>
        <span style={{ fontWeight: 600, color: 'var(--color-accent-mint)' }}>
          {stage ? `Stage: ${stage}` : 'Processing...'}
        </span>
        {percent !== null && <span>{done} / {total} ({percent}%)</span>}
      </div>
      <div style={{ width: '100%', height: '4px', background: 'var(--color-surface-raised)', borderRadius: '2px', overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            background: 'var(--color-accent-mint)',
            width: percent !== null ? `${percent}%` : '50%',
            transition: 'width 200ms ease',
          }}
        />
      </div>
    </div>
  );
}

