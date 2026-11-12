import { useState } from 'react';
import type { HuntItem, HuntResult } from '../../backend/types';
import { Badge } from '../Workbench';

interface HunterNodeMapProps {
  huntResult: HuntResult;
}

export function HunterNodeMap({ huntResult }: HunterNodeMapProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>(huntResult.roots[0] ?? null);
  const [lowExpanded, setLowExpanded] = useState(false);

  const roots = huntResult.roots;
  const items = huntResult.items;

  // Map findings to roots if path matches, or artifact
  const findingsForRoot = (root: string) => {
    return items.filter((it) => it.path && it.path.startsWith(root));
  };

  const selectedFindings = selectedNode ? findingsForRoot(selectedNode) : [];
  const highMediumFindings = selectedFindings.filter((it) => it.severity.toUpperCase() !== 'LOW');
  const lowFindings = selectedFindings.filter((it) => it.severity.toUpperCase() === 'LOW');
  const lowPackagesCount = new Set(lowFindings.map((it) => it.dist || it.artifact || 'environment')).size;

  const renderFindingItem = (item: HuntItem, idx: number | string) => (
    <li
      key={idx}
      style={{
        background: 'var(--color-surface-raised)',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-sm)',
        padding: 'var(--space-3)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-1)' }}>
        <strong><code>{item.artifact}</code></strong>
        <Badge tone={item.severity.toUpperCase() === 'HIGH' ? 'danger' : item.severity.toUpperCase() === 'MEDIUM' ? 'amber' : 'neutral'}>
          {item.severity}
        </Badge>
      </div>
      <p style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-2)' }}>{item.reason}</p>
      {item.evidence_snippet && (
        <pre
          style={{
            background: 'var(--color-surface-sunken)',
            border: '1px solid var(--color-border)',
            padding: 'var(--space-2)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-xs)',
            color: 'var(--color-accent-mint)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            overflowWrap: 'anywhere',
            maxWidth: '100%',
          }}
        >
          <code>{item.evidence_snippet}</code>
        </pre>
      )}
    </li>
  );

  return (
    <div className="panel" style={{ marginTop: 'var(--space-4)' }}>
      <h3>Inspected Roots & Findings Map</h3>
      <p className="helper-text" style={{ marginBottom: 'var(--space-4)' }}>
        Inspected environment directories from the hunt report. Nodes with recorded findings are highlighted.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 1fr) minmax(320px, 2fr)', gap: 'var(--space-4)' }}>
        {/* Nodes list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          <h4 style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>
            Environment Roots ({roots.length})
          </h4>
          {roots.map((root) => {
            const count = findingsForRoot(root).length;
            const isSelected = selectedNode === root;
            const hasFindings = count > 0;

            return (
              <button
                key={root}
                type="button"
                onClick={() => setSelectedNode(root)}
                style={{
                  textAlign: 'left',
                  background: isSelected ? 'var(--color-surface-raised)' : 'transparent',
                  border: isSelected
                    ? '1px solid var(--color-accent-mint)'
                    : hasFindings
                    ? '1px solid var(--color-accent-amber)'
                    : '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 'var(--space-2) var(--space-3)',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }}>
                  <code style={{ fontSize: 'var(--text-xs)' }}>{root}</code>
                </div>
                {hasFindings ? (
                  <Badge tone="amber">{count} findings</Badge>
                ) : (
                  <Badge tone="ok">None</Badge>
                )}
              </button>
            );
          })}
        </div>

        {/* Selected root detail */}
        <div>
          {selectedNode ? (
            <div>
              <h4 style={{ wordBreak: 'break-all', marginBottom: 'var(--space-2)' }}>
                <code>{selectedNode}</code>
              </h4>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-3)' }}>
                {selectedFindings.length} findings associated with this inspected root.
              </p>

              {selectedFindings.length === 0 ? (
                <p className="helper-text">No findings or anomalies recorded in this environment directory.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                  {highMediumFindings.length > 0 && (
                    <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                      {highMediumFindings.map((item, idx) => renderFindingItem(item, `hm-${idx}`))}
                    </ul>
                  )}

                  {lowFindings.length > 0 && (
                    <div style={{ marginTop: 'var(--space-2)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                          Low severity ({lowFindings.length})
                        </span>
                        <button
                          type="button"
                          className="button button--secondary"
                          onClick={() => setLowExpanded(!lowExpanded)}
                          style={{ fontSize: 'var(--text-xs)', padding: '2px 8px' }}
                        >
                          {lowExpanded ? 'Collapse LOW findings' : `Expand ${lowFindings.length} low findings in ${lowPackagesCount} packages`}
                        </button>
                      </div>
                      <p className="helper-text" style={{ margin: '0 0 var(--space-2)', fontSize: 'var(--text-xs)' }}>
                        LOW findings are usually normal tooling code (e.g. build shims, namespace declarations, or system-managed hooks).
                      </p>
                      {lowExpanded && (
                        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                          {lowFindings.map((item, idx) => renderFindingItem(item, `low-${idx}`))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <p className="helper-text">Select a root directory on the left.</p>
          )}
        </div>
      </div>
    </div>
  );
}

