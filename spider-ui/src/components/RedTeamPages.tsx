import { useState, useEffect } from 'react';
import { backend } from '../backend';
import { Badge, PageHeader, SectionHeading } from './Workbench';
import { AnimatedNumber } from './visuals/AnimatedNumber';

interface ResultsShape {
  evasion: {
    source: string;
    samples: number;
    suspicious: number;
    review_only: number;
    silent: number;
    note: string;
  };
  limits: string[];
}

export function RedTeamOverview() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as unknown as ResultsShape)).catch(() => {});
  }, []);

  return (
    <div className="page">
      <PageHeader
        section="Red Team"
        title="Overview"
        description="Controlled synthetic evasion tests against SPIDER static AST inspection."
      />

      <div className="notice notice--cyan" role="status" style={{ marginBottom: 'var(--space-6)' }}>
        Controlled test suite. SPIDER operates as a static analyser and never executes packages.
      </div>

      {data && (
        <div className="stat-strip stat-strip--cards">
          <div className="stat-card">
            <strong><AnimatedNumber value={data.evasion.samples} /></strong>
            <span>Synthetic test samples</span>
          </div>
          <div className="stat-card">
            <strong><AnimatedNumber value={data.evasion.suspicious} /></strong>
            <span>Flagged suspicious</span>
          </div>
          <div className="stat-card">
            <strong><AnimatedNumber value={data.evasion.review_only} /></strong>
            <span>Flagged review-only</span>
          </div>
          <div className="stat-card">
            <strong><AnimatedNumber value={data.evasion.silent} /></strong>
            <span>Silent at verdict level</span>
          </div>
        </div>
      )}

      {/* Stage 4: 12-sample outcome strip */}
      {data && (
        <section className="panel" style={{ marginTop: 'var(--space-4)' }}>
          <SectionHeading title="Adversarial Outcome Strip (12 Samples)" aside={<Badge tone="neutral">results.json</Badge>} />
          <div style={{ marginTop: 'var(--space-3)' }}>
            <div style={{ display: 'flex', height: '24px', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
              <div
                style={{ width: `${(data.evasion.suspicious / data.evasion.samples) * 100}%`, background: 'var(--color-accent-amber)' }}
                title={`Suspicious: ${data.evasion.suspicious} of ${data.evasion.samples}`}
              />
              <div
                style={{ width: `${(data.evasion.review_only / data.evasion.samples) * 100}%`, background: 'var(--color-accent-mint)' }}
                title={`Review only: ${data.evasion.review_only} of ${data.evasion.samples}`}
              />
              <div
                style={{ width: `${(data.evasion.silent / data.evasion.samples) * 100}%`, background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)' }}
                title={`Silent: ${data.evasion.silent} of ${data.evasion.samples}`}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', marginTop: 'var(--space-2)', color: 'var(--color-text-muted)' }}>
              <span>🟧 Suspicious ({data.evasion.suspicious})</span>
              <span>🟩 Review only ({data.evasion.review_only})</span>
              <span>⬜ Silent at verdict level ({data.evasion.silent})</span>
            </div>
          </div>
        </section>
      )}

      <div className="panel" style={{ marginTop: 'var(--space-4)' }}>
        <SectionHeading title="Methodology and Scope" aside={<Badge tone="neutral">Static Only</Badge>} />
        <p>
          The Red Team evaluation module tracks how synthetic packaging disguises bypass static AST rules.
          Because SPIDER never executes package code, evasion focuses on AST fragmentation, string obfuscation, and unconventional packaging entrypoints.
        </p>
      </div>
    </div>
  );
}

export function RedTeamBatch() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as unknown as ResultsShape)).catch(() => {});
  }, []);

  return (
    <div className="page">
      <PageHeader
        section="Red Team"
        title="Batch"
        description="The 12-sample adversarial verification batch from results.json."
      />

      {data && (
        <section className="panel">
          <SectionHeading title="Adversarial Batch Verification (12 Samples)" aside={<Badge tone="neutral">results.json</Badge>} />
          <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
            <dt>Total synthetic samples:</dt>
            <dd><strong><AnimatedNumber value={data.evasion.samples} /></strong></dd>
            <dt>Suspicious verdict:</dt>
            <dd><AnimatedNumber value={data.evasion.suspicious} /></dd>
            <dt>Review only flags:</dt>
            <dd><AnimatedNumber value={data.evasion.review_only} /></dd>
            <dt>Silent at verdict level:</dt>
            <dd><AnimatedNumber value={data.evasion.silent} /></dd>
          </dl>
          <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
            Note: {data.evasion.note}
          </p>
          <small className="muted" style={{ display: 'block', marginTop: 'var(--space-2)' }}>
            Source: {data.evasion.source}
          </small>

          <p className="helper-text" style={{ marginTop: 'var(--space-4)' }}>
            Per-sample outcomes are recorded in the repository file above. They are not bundled in this interface, so none are shown here.
          </p>
        </section>
      )}
    </div>
  );
}

export function RedTeamTechniques() {
  const techniques = [
    { name: 'ROT13 & Simple Ciphers', status: 'Illustrative', desc: 'Encoding payload strings in ROT13 or basic substitution. SPIDER does not treat ROT13 as obfuscation by default.' },
    { name: 'AST Node Fragmentation', status: 'Illustrative', desc: 'Splitting sensitive calls (e.g. eval, exec, subprocess) across multiple chained lambda or function references.' },
    { name: 'Dynamic Attribute Resolution', status: 'Illustrative', desc: 'Accessing builtins via getattr(__builtins__, ...) using computed or concatenated identifier strings.' },
    { name: 'Metadata & Setup Deferral', status: 'Illustrative', desc: 'Moving execution from setup.py to custom build hooks or entry points that evade basic top-level inspection.' },
  ];

  return (
    <div className="page">
      <PageHeader
        section="Red Team"
        title="Techniques"
        description="Catalog of evasion mechanisms evaluated against static analysis."
      />

      {/* Stage 4: Labelled Illustrative diagram comparing original vs modified structure */}
      <section className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <SectionHeading title="Original vs Modified Code Structure" aside={<span className="illustrative-tag">Illustrative</span>} />
        <p className="helper-text" style={{ marginBottom: 'var(--space-3)' }}>
          Conceptual illustration of how payload splitting fragments AST nodes without changing semantic runtime behavior.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(16rem, 100%), 1fr))', gap: 'var(--space-4)' }}>
          <div style={{ minWidth: 0, background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', padding: 'var(--space-3)' }}>
            <h5 style={{ color: 'var(--color-accent-amber)', marginBottom: 'var(--space-2)' }}>Direct Form (Flagged)</h5>
            <pre style={{ fontSize: 'var(--text-xs)', overflowX: 'auto', color: 'var(--color-text-primary)' }}>
              <code>{`import subprocess\nsubprocess.run(["curl", url])`}</code>
            </pre>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: 'var(--space-2)' }}>
              Illustrative: a direct call like this is the kind of pattern the rules look for.
            </p>
          </div>
          <div style={{ minWidth: 0, background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', padding: 'var(--space-3)' }}>
            <h5 style={{ color: 'var(--color-accent-mint)', marginBottom: 'var(--space-2)' }}>Fragmented Form (Disguised)</h5>
            <pre style={{ fontSize: 'var(--text-xs)', overflowX: 'auto', color: 'var(--color-text-primary)' }}>
              <code>{`m = __import__("sub" + "process")\ngetattr(m, "r" + "un")(["c"+"url", url])`}</code>
            </pre>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: 'var(--space-2)' }}>
              Splits token literals across concatenation operations.
            </p>
          </div>
        </div>
      </section>

      <div className="results-grid">
        {techniques.map((t, idx) => (
          <section key={idx} className="panel">
            <SectionHeading title={t.name} aside={<span className="illustrative-tag">{t.status}</span>} />
            <p>{t.desc}</p>
          </section>
        ))}
      </div>
    </div>
  );
}

export function RedTeamLimits() {
  return (
    <div className="page">
      <PageHeader
        section="Red Team"
        title="Limits"
        description="Caveats and constraints of the current adversarial test suite."
      />

      <div className="panel">
        <SectionHeading title="Adversarial Testing Boundaries" aside={<Badge tone="amber">Caveats</Badge>} />
        <ul className="limitation-list">
          <li><strong>One payload type:</strong> The 12-sample adversarial batch is constructed around variations of a single payload mechanism.</li>
          <li><strong>ROT13 unflagged:</strong> ROT13 string transformations are explicitly not treated as obfuscation in the static rules.</li>
          <li><strong>Silent at verdict level:</strong> Attack Success Rate (ASR) is strictly defined as "samples silent at verdict level", not package execution success.</li>
          <li><strong>Baseline caveat:</strong> Static analysis has no execution visibility; dynamic execution tracking is outside current tool architecture.</li>
        </ul>
      </div>
    </div>
  );
}
