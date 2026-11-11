import { useState, useEffect } from 'react';
import { backend } from '../backend';
import { Badge, PageHeader, SectionHeading } from './Workbench';
import { ResultsReading } from './Guidance';

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

export function ResearchPage() {
  const [data, setData] = useState<ResultsShape | null>(null);

  useEffect(() => {
    backend.getResults().then((res) => setData(res as ResultsShape)).catch(() => {});
  }, []);

  if (!data) {
    return (
      <div className="page">
        <PageHeader section="Research" title="Results" description="Loading measured numbers..." />
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        section="Research"
        title="Results"
        description="Measured numbers and known limitations from recorded test runs."
      />

      <div className="notice notice--cyan" role="status" style={{ marginBottom: 'var(--space-6)' }}>
        These are signal rates, not detection accuracy.
      </div>

      <div className="stat-strip">
        <div><strong>{data.corpus.malicious_packages.toLocaleString()}</strong><span>malicious-labelled packages scanned</span></div>
        <div><strong>{data.corpus.benign_packages.toLocaleString()}</strong><span>benign packages scanned</span></div>
        <div><strong>{data.corpus.suspicious_pct.malicious}% vs {data.corpus.suspicious_pct.benign}%</strong><span>flagged suspicious: malicious vs benign</span></div>
        <div><strong>{data.false_positive.false_positives} of {data.false_positive.flagged}</strong><span>flags were false alarms in the 100-package check</span></div>
      </div>

      <div className="results-grid">
        {/* Card 1: Corpus signals */}
        <section className="panel">
          <SectionHeading title="Corpus signals" aside={<Badge tone="neutral">Corpus</Badge>} />
          <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
            <dt>Malicious packages:</dt>
            <dd><strong>{data.corpus.malicious_packages}</strong></dd>
            <dt>Benign packages:</dt>
            <dd><strong>{data.corpus.benign_packages}</strong></dd>
            <dt>Suspicious rate (malicious):</dt>
            <dd>{data.corpus.suspicious_pct.malicious}%</dd>
            <dt>Suspicious rate (benign):</dt>
            <dd>{data.corpus.suspicious_pct.benign}%</dd>
            <dt>Unable to assess (malicious):</dt>
            <dd>{data.corpus.unable_to_assess_pct.malicious}%</dd>
            <dt>Unable to assess (benign):</dt>
            <dd>{data.corpus.unable_to_assess_pct.benign}%</dd>
            <dt>Median Python files:</dt>
            <dd>{data.corpus.median_py_files.malicious} (malicious) vs {data.corpus.median_py_files.benign} (benign)</dd>
          </dl>
          <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
            What this means: {data.corpus.note} It does not mean package detection is 100% complete.
          </p>
          <small className="muted" style={{ display: 'block', marginTop: 'var(--space-2)' }}>
            Source: {data.corpus.source}
          </small>
        </section>

        {/* Card 2: False-positive check */}
        <section className="panel">
          <SectionHeading title="False-positive check" aside={<Badge tone="neutral">Validation</Badge>} />
          <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
            <dt>Packages checked:</dt>
            <dd><strong>{data.false_positive.packages}</strong></dd>
            <dt>Flagged packages:</dt>
            <dd>{data.false_positive.flagged}</dd>
            <dt>False positives:</dt>
            <dd>{data.false_positive.false_positives}</dd>
            <dt>Unclear results:</dt>
            <dd>{data.false_positive.unclear}</dd>
            <dt>FP rate:</dt>
            <dd>{data.false_positive.fp_pct}% (Wilson 95% CI: [{data.false_positive.wilson_95[0]}%, {data.false_positive.wilson_95[1]}%])</dd>
          </dl>
          <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
            What this means: {data.false_positive.note} It does not represent broader package repositories.
          </p>
          <small className="muted" style={{ display: 'block', marginTop: 'var(--space-2)' }}>
            Source: {data.false_positive.source}
          </small>
        </section>

        {/* Card 3: Evasion batch */}
        <section className="panel">
          <SectionHeading title="Evasion batch" aside={<Badge tone="neutral">Adversarial</Badge>} />
          <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
            <dt>Total synthetic samples:</dt>
            <dd><strong>{data.evasion.samples}</strong></dd>
            <dt>Suspicious:</dt>
            <dd>{data.evasion.suspicious}</dd>
            <dt>Review only:</dt>
            <dd>{data.evasion.review_only}</dd>
            <dt>Silent:</dt>
            <dd>{data.evasion.silent}</dd>
          </dl>
          <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
            What this means: {data.evasion.note} It does not prove resilience against arbitrary evasion.
          </p>
          <small className="muted" style={{ display: 'block', marginTop: 'var(--space-2)' }}>
            Source: {data.evasion.source}
          </small>
        </section>

        {/* Card 4: Known limits */}
        <section className="panel">
          <SectionHeading title="Known limits" aside={<Badge tone="amber">Limits</Badge>} />
          <ul className="limitation-list">
            {data.limits.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
          <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
            What this means: Static analysis has firm boundaries; uninspected code requires runtime sandboxing.
          </p>
        </section>
      </div>

      <ResultsReading />

      <div>
        <section className="panel">
          <SectionHeading title="Model metrics" />
          <p className="muted">Model metrics: under review, not shown</p>
        </section>
      </div>
    </div>
  );
}

