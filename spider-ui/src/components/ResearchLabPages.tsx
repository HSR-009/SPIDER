import { useState, useEffect } from 'react';
import { backend } from '../backend';
import { Badge, PageHeader, SectionHeading } from './Workbench';
import { AnimatedNumber } from './visuals/AnimatedNumber';

interface ResultsShape {
  corpus: {
    source: string;
    malicious_packages: number;
    benign_packages: number;
    suspicious_pct: { malicious: number; benign: number };
    unable_to_assess_pct: { malicious: number; benign: number };
    median_py_files: { malicious: number; benign: number };
    note: string;
  };
  false_positive: {
    source: string;
    packages: number;
    flagged: number;
    false_positives: number;
    unclear: number;
    fp_pct: number;
    wilson_95: [number, number];
    note: string;
  };
  limits: string[];
}

export function ResearchOverview() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as unknown as ResultsShape)).catch(() => {});
  }, []);

  return (
    <div className="page">
      <PageHeader
        section="Research Lab"
        title="Overview"
        description="Empirical benchmark data, signal distributions, and verification findings from PyPI static analysis."
      />

      <div className="notice notice--cyan" role="status" style={{ marginBottom: 'var(--space-6)' }}>
        Static analysis only. All numbers originate from verified scan records in results.json.
      </div>

      {data && (
        <div className="stat-strip stat-strip--cards">
          <div className="stat-card">
            <strong><AnimatedNumber value={data.corpus.malicious_packages} /></strong>
            <span>Malicious corpus packages</span>
          </div>
          <div className="stat-card">
            <strong><AnimatedNumber value={data.corpus.benign_packages} /></strong>
            <span>Benign corpus packages</span>
          </div>
          <div className="stat-card">
            <strong>{data.corpus.suspicious_pct.malicious}%</strong>
            <span>Malicious flagged suspicious</span>
          </div>
          <div className="stat-card">
            <strong>{data.false_positive.fp_pct}%</strong>
            <span>Validation false-positive rate</span>
          </div>
        </div>
      )}

      {/* Stage 4: Corpus bars comparing malicious vs benign signal rates */}
      {data && (
        <section className="panel" style={{ marginTop: 'var(--space-4)' }}>
          <SectionHeading title="Corpus Signal Proportions" aside={<Badge tone="neutral">results.json</Badge>} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)', marginTop: 'var(--space-3)' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-sm)', marginBottom: '4px' }}>
                <span>Malicious packages flagged suspicious</span>
                <strong>{data.corpus.suspicious_pct.malicious}%</strong>
              </div>
              <div style={{ width: '100%', height: '12px', background: 'var(--color-surface-sunken)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                <div style={{ width: `${data.corpus.suspicious_pct.malicious}%`, height: '100%', background: 'var(--color-accent-amber)' }} />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-sm)', marginBottom: '4px' }}>
                <span>Benign packages flagged suspicious</span>
                <strong>{data.corpus.suspicious_pct.benign}%</strong>
              </div>
              <div style={{ width: '100%', height: '12px', background: 'var(--color-surface-sunken)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                <div style={{ width: `${data.corpus.suspicious_pct.benign}%`, height: '100%', background: 'var(--color-accent-mint)' }} />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-sm)', marginBottom: '4px' }}>
                <span>False-positive rate (Wilson 95% CI: [{data.false_positive.wilson_95[0]}%, {data.false_positive.wilson_95[1]}%])</span>
                <strong>{data.false_positive.fp_pct}%</strong>
              </div>
              <div style={{ width: '100%', height: '12px', background: 'var(--color-surface-sunken)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                <div style={{ width: `${data.false_positive.fp_pct}%`, height: '100%', background: 'var(--color-text-muted)' }} />
              </div>
            </div>
          </div>
        </section>
      )}

      <div className="panel" style={{ marginTop: 'var(--space-4)' }}>
        <SectionHeading title="Research Scope and Methodology" aside={<Badge tone="neutral">Scope</Badge>} />
        <p>
          SPIDER evaluates Python packages solely through AST examination, packaging metadata rules, and environment persistence vectors.
          Packages are never executed. These research sections document signal yields, corpus characteristics, and established technical boundaries.
        </p>
      </div>
    </div>
  );
}

export function ResearchDataset() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as unknown as ResultsShape)).catch(() => {});
  }, []);

  return (
    <div className="page">
      <PageHeader
        section="Research Lab"
        title="Dataset"
        description="Corpus numbers, source provenance, and size metrics from results.json."
      />

      {data && (
        <div className="results-grid">
          <section className="panel">
            <SectionHeading title="Corpus Scale" aside={<Badge tone="cyan">Corpus</Badge>} />
            <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
              <dt>Malicious packages:</dt>
              <dd><strong><AnimatedNumber value={data.corpus.malicious_packages} /></strong></dd>
              <dt>Benign packages:</dt>
              <dd><strong><AnimatedNumber value={data.corpus.benign_packages} /></strong></dd>
              <dt>Median Python files (malicious):</dt>
              <dd>{data.corpus.median_py_files.malicious}</dd>
              <dt>Median Python files (benign):</dt>
              <dd>{data.corpus.median_py_files.benign}</dd>
            </dl>
            <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
              Source: {data.corpus.source}
            </p>
          </section>

          <section className="panel">
            <SectionHeading title="Validation Set" aside={<Badge tone="neutral">Validation</Badge>} />
            <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
              <dt>Packages checked:</dt>
              <dd><strong><AnimatedNumber value={data.false_positive.packages} /></strong></dd>
              <dt>Flagged count:</dt>
              <dd>{data.false_positive.flagged}</dd>
              <dt>False positives:</dt>
              <dd>{data.false_positive.false_positives}</dd>
              <dt>Wilson 95% Interval:</dt>
              <dd>[{data.false_positive.wilson_95[0]}%, {data.false_positive.wilson_95[1]}%]</dd>
            </dl>
            <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
              Source: {data.false_positive.source}
            </p>
          </section>
        </div>
      )}
    </div>
  );
}

export function ResearchSignals() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as unknown as ResultsShape)).catch(() => {});
  }, []);

  return (
    <div className="page">
      <PageHeader
        section="Research Lab"
        title="Signals"
        description="Signal detection yields, unable-to-assess proportions, and size confounding factors."
      />

      <div className="notice notice--cyan" role="status" style={{ marginBottom: 'var(--space-6)' }}>
        Signal rates, not detection accuracy. Package size alone separates the classes (size-only AUC about 0.79).
      </div>

      {data && (
        <div className="results-grid">
          <section className="panel">
            <SectionHeading title="Signal Proportions" aside={<Badge tone="neutral">AST & Rules</Badge>} />
            <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
              <dt>Suspicious rate (malicious corpus):</dt>
              <dd><strong>{data.corpus.suspicious_pct.malicious}%</strong></dd>
              <dt>Suspicious rate (benign corpus):</dt>
              <dd><strong>{data.corpus.suspicious_pct.benign}%</strong></dd>
              <dt>Unable to assess (malicious):</dt>
              <dd>{data.corpus.unable_to_assess_pct.malicious}%</dd>
              <dt>Unable to assess (benign):</dt>
              <dd>{data.corpus.unable_to_assess_pct.benign}%</dd>
            </dl>
          </section>

          <section className="panel">
            <SectionHeading title="Size Confounder Note" aside={<Badge tone="amber">Confounder</Badge>} />
            <p className="helper-text">
              {data.corpus.note}
            </p>
            <p style={{ marginTop: 'var(--space-3)' }}>
              Median file count in malicious samples is {data.corpus.median_py_files.malicious} files versus {data.corpus.median_py_files.benign} in benign packages.
              Consequently, simplistic volume metrics produce spurious separation without genuine semantic verification.
            </p>
          </section>
        </div>
      )}
    </div>
  );
}

export function ResearchModels() {
  return (
    <div className="page">
      <PageHeader
        section="Research Lab"
        title="Models"
        description="Current state of statistical and learned classification models in SPIDER."
      />

      <div className="panel">
        <SectionHeading title="Model Metrics Status" aside={<Badge tone="amber">Under Review</Badge>} />
        <p>
          Model metrics are under review and not shown. Earlier reported machine-learning figures conflicted with the project's own verified measurements and are being re-checked, so none are displayed.
        </p>
      </div>

      <div style={{ marginTop: 'var(--space-6)', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-4)' }}>
        <div className="planned-chart-frame">
          <span className="planned-tag">Planned</span>
          <h4>ROC Curve</h4>
          <p className="muted" style={{ fontSize: 'var(--text-xs)' }}>Frame reserved for verified receiver operating characteristic evaluations.</p>
        </div>
        <div className="planned-chart-frame">
          <span className="planned-tag">Planned</span>
          <h4>PR Curve</h4>
          <p className="muted" style={{ fontSize: 'var(--text-xs)' }}>Frame reserved for precision-recall curves across balanced test partitions.</p>
        </div>
        <div className="planned-chart-frame">
          <span className="planned-tag">Planned</span>
          <h4>Feature Attribution (SHAP)</h4>
          <p className="muted" style={{ fontSize: 'var(--text-xs)' }}>Frame reserved for local interpretability distributions once model weights stabilize.</p>
        </div>
      </div>
    </div>
  );
}

export function ResearchLimits() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as unknown as ResultsShape)).catch(() => {});
  }, []);

  return (
    <div className="page">
      <PageHeader
        section="Research Lab"
        title="Limits"
        description="Rigorous boundaries of static package inspection."
      />

      <div className="panel">
        <SectionHeading title="Established Operational Limits" aside={<Badge tone="amber">Limits</Badge>} />
        {data && (
          <ul className="limitation-list">
            {data.limits.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        )}
        <p className="helper-text" style={{ marginTop: 'var(--space-4)' }}>
          Static analysis never executes code. Dynamic payloads or uninspected extensions require dedicated runtime sandboxes.
        </p>
      </div>
    </div>
  );
}
