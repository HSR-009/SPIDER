import { useState } from 'react';
import type { Finding } from '../../backend/types';
import { Badge } from '../Workbench';

interface FileTreePanelProps {
  findings: Finding[];
}

export function FileTreePanel({ findings }: FileTreePanelProps) {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(findings[0] ?? null);

  // Group findings by file
  const fileMap = new Map<string, Finding[]>();
  findings.forEach((f) => {
    const list = fileMap.get(f.file) ?? [];
    list.push(f);
    fileMap.set(f.file, list);
  });

  const files = Array.from(fileMap.keys());

  if (findings.length === 0) {
    return (
      <div className="panel" style={{ marginTop: 'var(--space-4)' }}>
        <h3>File Tree & Evidence</h3>
        <p className="helper-text" style={{ marginTop: 'var(--space-2)' }}>
          No findings were recorded in the inspected files.
        </p>
      </div>
    );
  }

  return (
    <div className="panel" style={{ marginTop: 'var(--space-4)' }}>
      <h3>File Tree & Evidence Attached to Findings</h3>
      <p className="helper-text" style={{ marginBottom: 'var(--space-4)' }}>
        Click any finding to inspect its line location, explanation, and inert code excerpt.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1fr) minmax(320px, 2fr)', gap: 'var(--space-4)' }}>
        {/* Left: Tree / list */}
        <div style={{ borderRight: '1px solid var(--color-border)', paddingRight: 'var(--space-3)' }}>
          <h4 style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: 'var(--space-2)' }}>
            Inspected Files with Findings ({files.length})
          </h4>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {files.map((file) => {
              const fileFindings = fileMap.get(file) ?? [];
              return (
                <li key={file} style={{ marginBottom: 'var(--space-2)' }}>
                  <div style={{ fontWeight: 600, fontSize: 'var(--text-sm)', marginBottom: '4px' }}>
                    📄 <code>{file}</code>
                  </div>
                  <ul style={{ listStyle: 'none', paddingLeft: 'var(--space-3)', margin: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {fileFindings.map((f, idx) => {
                      const isSelected = selectedFinding === f;
                      const tone = f.severity.toUpperCase() === 'HIGH' ? 'danger' : f.severity.toUpperCase() === 'MEDIUM' ? 'warning' : 'neutral';
                      return (
                        <li key={idx}>
                          <button
                            type="button"
                            onClick={() => setSelectedFinding(f)}
                            style={{
                              width: '100%',
                              textAlign: 'left',
                              background: isSelected ? 'var(--color-surface-raised)' : 'transparent',
                              border: isSelected ? '1px solid var(--color-accent-mint)' : '1px solid transparent',
                              borderRadius: 'var(--radius-sm)',
                              padding: '4px 8px',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              gap: 'var(--space-2)',
                            }}
                          >
                            <span style={{ fontSize: 'var(--text-xs)', fontFamily: 'monospace' }}>
                              {f.indicator} {f.span?.start_line ? `(L${f.span.start_line})` : ''}
                            </span>
                            <Badge tone={tone as any}>{f.severity}</Badge>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Right: Selected Finding & Excerpt */}
        <div>
          {selectedFinding ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                <h4>
                  <code>{selectedFinding.file}</code>
                  {selectedFinding.span?.start_line && (
                    <span style={{ color: 'var(--color-accent-mint)', marginLeft: 'var(--space-2)' }}>
                      : Line {selectedFinding.span.start_line}
                    </span>
                  )}
                </h4>
                <Badge tone={selectedFinding.severity.toUpperCase() === 'HIGH' ? 'danger' : 'warning'}>
                  {selectedFinding.severity} · {selectedFinding.category}
                </Badge>
              </div>

              <p style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-3)' }}>
                {selectedFinding.explanation || 'No description provided by rule.'}
              </p>

              {selectedFinding.snippet ? (
                <div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                    Inert source excerpt (AST context):
                  </div>
                  <pre
                    style={{
                      background: 'var(--color-surface-sunken)',
                      border: '1px solid var(--color-border)',
                      padding: 'var(--space-3)',
                      borderRadius: 'var(--radius-sm)',
                      overflowX: 'auto',
                      fontSize: 'var(--text-sm)',
                      color: 'var(--color-accent-mint)',
                    }}
                  >
                    <code>{selectedFinding.snippet}</code>
                  </pre>
                </div>
              ) : (
                <p className="helper-text">No source snippet was attached to this AST finding.</p>
              )}
            </div>
          ) : (
            <p className="helper-text">Select a finding on the left to examine details.</p>
          )}
        </div>
      </div>
    </div>
  );
}

