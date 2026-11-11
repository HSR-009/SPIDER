import { useState, useEffect, type FormEvent } from 'react';
import { NavLink, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import type { Finding, HuntItem, HuntResult, ScanRecord } from '../backend/types';
import { formatVerdictOutcome } from '../backend/parseRecord';
import { useWorkbenchStore } from '../state/workbench';
import { Badge, PageHeader, SectionHeading } from './Workbench';
import { VerdictKey, ScanSteps, HunterChecks, HistoryTips } from './Guidance';
import { AnimatedNumber } from './visuals/AnimatedNumber';
import { FileTreePanel } from './visuals/FileTreePanel';
import { ProgressStrip } from './visuals/ProgressStrip';
import { HunterNodeMap } from './visuals/HunterNodeMap';

const DISCLAIMER = "Static analysis only. 'None detected in this scan' does not mean the package is safe.";

const REASON_LABELS: Record<string, string> = {
  S1_install_command: 'Install hook overrides',
  uninspected_ratio: 'High uninspected file ratio',
  native_code: 'Native binary extension present',
  eval_exec: 'Dynamic execution call',
  network_access: 'Network socket or request call',
};

function humanReason(reason: string): string {
  return REASON_LABELS[reason] || reason;
}

function escapeMarkdown(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

// -------------------------------------------------------------
// 1. SCANNER: Scan Page (/scanner/scan)
// -------------------------------------------------------------
export function ScannerScanPage() {
  const navigate = useNavigate();
  const { startScan, isScanning, scanProgress, scanError } = useWorkbenchStore();
  const [tab, setTab] = useState<'upload' | 'folder'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [folderPath, setFolderPath] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setValidationError(null);
    const chosen = e.target.files?.[0] || null;
    if (!chosen) {
      setFile(null);
      return;
    }
    const name = chosen.name.toLowerCase();
    if (!name.endsWith('.whl') && !name.endsWith('.tar.gz')) {
      setValidationError('Please select a .whl or .tar.gz package archive.');
      setFile(null);
      return;
    }
    setFile(chosen);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    if (tab === 'upload') {
      if (!file) {
        setValidationError('Please choose a file to scan.');
        return;
      }
      const scanId = await startScan(file);
      if (scanId) {
        navigate('/scanner/result');
      }
    } else {
      if (!folderPath.trim()) {
        setValidationError('Please enter a folder path.');
        return;
      }
      const scanId = await startScan({ path: folderPath.trim() });
      if (scanId) {
        navigate('/scanner/result');
      }
    }
  };

  return (
    <div className="page">
      <PageHeader
        section="Package Scanner"
        title="Scan a package"
        description="Check one package before you trust it."
      />

      <section className="panel" style={{ maxWidth: '640px' }}>
        <SectionHeading title="Submit package for static inspection" />

        <div className="tab-bar" style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
          <button
            type="button"
            className={`button ${tab === 'upload' ? 'button--primary' : 'button--secondary'}`}
            onClick={() => { setTab('upload'); setValidationError(null); }}
          >
            Archive upload
          </button>
          <button
            type="button"
            className={`button ${tab === 'folder' ? 'button--primary' : 'button--secondary'}`}
            onClick={() => { setTab('folder'); setValidationError(null); }}
          >
            Folder path
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {tab === 'upload' ? (
            <div style={{ marginBottom: 'var(--space-4)' }}>
              <label htmlFor="package-file">Drop a .whl or .tar.gz, or choose a file</label>
              <input
                id="package-file"
                key="package-file"
                type="file"
                accept=".whl,.tar.gz"
                disabled={isScanning}
                onChange={handleFileChange}
              />
              {file && (
                <p className="helper-text" style={{ marginTop: 'var(--space-2)' }}>
                  Selected: <code>{file.name}</code> ({Math.round(file.size / 1024)} KB)
                </p>
              )}
            </div>
          ) : (
            <div style={{ marginBottom: 'var(--space-4)' }}>
              <label htmlFor="folder-path">Folder path to unpackaged source</label>
              <input
                id="folder-path"
                key="folder-path"
                type="text"
                placeholder="/path/to/package or C:\path\to\package"
                value={folderPath}
                disabled={isScanning}
                onChange={(e) => setFolderPath(e.target.value)}
              />
            </div>
          )}

          {validationError && (
            <p className="notice notice--amber" role="alert" style={{ marginBottom: 'var(--space-4)' }}>
              {validationError}
            </p>
          )}

          {scanError && (
            <p className="notice notice--amber" role="alert" style={{ marginBottom: 'var(--space-4)' }}>
              {scanError}
            </p>
          )}

          {isScanning && (
            <ProgressStrip
              stage={scanProgress?.stage}
              done={scanProgress?.done}
              total={scanProgress?.total}
            />
          )}

          <button
            type="submit"
            className="button button--primary"
            disabled={isScanning || (tab === 'upload' ? !file : !folderPath.trim())}
          >
            {isScanning ? 'Inspecting...' : 'Start scan'}
          </button>
        </form>
      </section>

      <ScanSteps />
    </div>
  );
}

// -------------------------------------------------------------
// 2. SCANNER: Result Page (/scanner/result)
// -------------------------------------------------------------
export function ScannerResultPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { currentRecord, loadScanRecord, currentRecordLoading, currentRecordError } = useWorkbenchStore();
  const requestedId = searchParams.get('id');

  useEffect(() => {
    if (requestedId && (!currentRecord || currentRecord.scan_id !== requestedId)) {
      void loadScanRecord(requestedId);
    }
  }, [requestedId]);

  if (currentRecordLoading) {
    return (
      <div className="page">
        <PageHeader section="Package Scanner" title="Result" description="Loading inspection record..." />
      </div>
    );
  }

  if (currentRecordError) {
    return (
      <div className="page">
        <PageHeader section="Package Scanner" title="Result" description="Record status" />
        <section className="panel">
          <p className="notice notice--amber">{currentRecordError}</p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <NavLink className="button button--primary" to="/scanner/scan">
              Scan a package
            </NavLink>
          </div>
        </section>
      </div>
    );
  }

  if (!currentRecord) {
    return (
      <div className="page">
        <PageHeader section="Package Scanner" title="Result" description="No scan selected" />
        <section className="panel">
          <p className="helper-text">No package has been scanned yet.</p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <NavLink className="button button--primary" to="/scanner/scan">
              Scan a package
            </NavLink>
          </div>
        </section>
        <VerdictKey />
      </div>
    );
  }

  const vOutcome = currentRecord.verdict.outcome;
  const outcomeText = formatVerdictOutcome(vOutcome);
  const tone = vOutcome === 'suspicious' ? 'danger' : vOutcome === 'unable_to_assess' ? 'warning' : 'ok';
  const topFindings = currentRecord.findings.slice(0, 3);
  const filesInspected = currentRecord.inventory.files_inspected ?? 0;
  const filesTotal = currentRecord.inventory.files_total ?? 0;
  const pyFiles = currentRecord.inventory.python_files ?? 0;

  return (
    <div className="page">
      <PageHeader
        section="Package Scanner"
        title={currentRecord.target?.name ?? currentRecord.scan_id}
        description={`Scan completed · ID: ${currentRecord.scan_id}`}
      />

      {/* Hero card with verdict first */}
      <section className={`dm-verdict dm-verdict--${tone}`} aria-label="Verdict">
        <div>
          <span className="eyebrow">Verdict</span>
          <h2>{outcomeText}</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
            {currentRecord.verdict.reasons.map((r) => (
              <span key={r} className="badge badge--neutral" title={`Raw id: ${r}`}>
                {humanReason(r)}
              </span>
            ))}
            {currentRecord.verdict.review_recommended && (
              <span className="badge badge--amber">Review recommended</span>
            )}
          </div>
        </div>

        <dl className="dm-stats">
          <div>
            <dt>Findings</dt>
            <dd>{currentRecord.findings.length}</dd>
          </div>
          <div>
            <dt>Files inspected</dt>
            <dd>{filesInspected}/{filesTotal}</dd>
          </div>
          <div>
            <dt>Python files</dt>
            <dd>{pyFiles}</dd>
          </div>
        </dl>

        {topFindings.length > 0 && (
          <div>
            <h3 style={{ fontSize: 'var(--text-base)', marginBottom: 'var(--space-2)' }}>Top findings:</h3>
            <ul className="dm-top">
              {topFindings.map((f, idx) => (
                <li key={idx}>
                  <strong className="badge badge--neutral">{f.severity}</strong>{' '}
                  <code>{f.indicator}</code>{' '}
                  <span className="muted">· {f.file}{f.span?.start_line ? `:${f.span.start_line}` : ''}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="action-row">
          <NavLink className="button button--primary" to="/scanner/evidence">
            View evidence
          </NavLink>
          <NavLink className="button button--secondary" to="/scanner/report">
            Export report
          </NavLink>
        </div>
      </section>

      {/* Collapsed Details section */}
      <details className="panel" style={{ marginTop: 'var(--space-4)' }}>
        <summary><strong>Inspection details & coverage</strong></summary>
        <div style={{ marginTop: 'var(--space-3)' }}>
          <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
            <dt>Package hash verified:</dt>
            <dd>{currentRecord.target?.hash_verified ? 'Verified' : 'Unverified'}</dd>
            <dt>Files total:</dt>
            <dd><AnimatedNumber value={filesTotal} /></dd>
            <dt>Files inspected:</dt>
            <dd><AnimatedNumber value={filesInspected} /></dd>
            <dt>Python files:</dt>
            <dd><AnimatedNumber value={pyFiles} /></dd>
            <dt>Parse failures:</dt>
            <dd>{currentRecord.inventory.parse_failures?.length ?? 0}</dd>
            <dt>Uninspected files:</dt>
            <dd>{(currentRecord.inventory.uninspected as string[])?.join(', ') || 'None'}</dd>
          </dl>

          {currentRecord.verdict.limitations && currentRecord.verdict.limitations.length > 0 && (
            <div style={{ marginTop: 'var(--space-4)' }}>
              <h4>Limitations:</h4>
              <ul className="limitation-list">
                {currentRecord.verdict.limitations.map((lim, i) => (
                  <li key={i}>{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </details>

      <p className="helper-text" style={{ marginTop: 'var(--space-6)' }}>
        {DISCLAIMER}
      </p>
    </div>
  );
}

// -------------------------------------------------------------
// 3. SCANNER: Evidence Page (/scanner/evidence)
// -------------------------------------------------------------
export function ScannerEvidencePage() {
  const { currentRecord } = useWorkbenchStore();
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  if (!currentRecord) {
    return (
      <div className="page">
        <PageHeader section="Package Scanner" title="Evidence" description="Findings inspection" />
        <section className="panel">
          <p className="helper-text">No active inspection selected.</p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <NavLink className="button button--primary" to="/scanner/scan">
              Scan a package
            </NavLink>
          </div>
        </section>
      </div>
    );
  }

  const allFindings = currentRecord.findings;
  const categories = Array.from(new Set(allFindings.map((f) => f.category)));
  const filtered = categoryFilter === 'ALL'
    ? allFindings
    : allFindings.filter((f) => f.category === categoryFilter);

  // Group by severity
  const high = filtered.filter((f) => f.severity.toUpperCase() === 'HIGH');
  const medium = filtered.filter((f) => f.severity.toUpperCase() === 'MEDIUM');
  const low = filtered.filter((f) => f.severity.toUpperCase() === 'LOW');
  const other = filtered.filter((f) => !['HIGH', 'MEDIUM', 'LOW'].includes(f.severity.toUpperCase()));

  const renderGroup = (title: string, list: Finding[], tone: string) => {
    if (list.length === 0) return null;
    return (
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <h3 style={{ marginBottom: 'var(--space-2)' }}>
          {title} ({list.length})
        </h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Category</th>
                <th>File:Line</th>
                <th>Explanation</th>
                <th>Snippet</th>
              </tr>
            </thead>
            <tbody>
              {list.map((f, i) => (
                <tr key={i}>
                  <td><code>{f.indicator}</code></td>
                  <td><span className="badge badge--neutral">{f.category}</span></td>
                  <td><code>{f.file}{f.span?.start_line ? `:${f.span.start_line}` : ''}</code></td>
                  <td>{f.explanation || '—'}</td>
                  <td>{f.snippet ? <code>{f.snippet}</code> : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  return (
    <div className="page">
      <PageHeader
        section="Package Scanner"
        title="Evidence"
        description={`Findings for ${currentRecord.target?.name ?? currentRecord.scan_id}`}
      />

      <section className="panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
          <SectionHeading title="Findings ledger" />
          {categories.length > 0 && (
            <div>
              <label htmlFor="cat-filter" style={{ display: 'inline', marginRight: 'var(--space-2)' }}>
                Category:
              </label>
              <select
                id="cat-filter"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                style={{ width: 'auto', display: 'inline-block' }}
              >
                <option value="ALL">All categories ({allFindings.length})</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {c} ({allFindings.filter((f) => f.category === c).length})
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {filtered.length === 0 ? (
          <p className="helper-text">No findings in the inspected files.</p>
        ) : (
          <>
            {renderGroup('High severity', high, 'danger')}
            {renderGroup('Medium severity', medium, 'warning')}
            {renderGroup('Low severity', low, 'neutral')}
            {renderGroup('Other findings', other, 'neutral')}
          </>
        )}
      </section>

      {/* Stage 3: File-tree panel attached to findings */}
      <FileTreePanel findings={allFindings} />

      <p className="helper-text" style={{ marginTop: 'var(--space-6)' }}>
        {DISCLAIMER}
      </p>
    </div>
  );
}

// -------------------------------------------------------------
// 4. SCANNER: Score Page (/scanner/score)
// -------------------------------------------------------------
export function ScannerScorePage() {
  const { currentRecord } = useWorkbenchStore();

  return (
    <div className="page">
      <PageHeader
        section="Package Scanner"
        title="Score"
        description="Model prediction and calibrated probability"
      />

      <section className="panel">
        <SectionHeading title="Model evaluation" />
        {currentRecord?.ml ? (
          <div>
            <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
              <dt>Model:</dt>
              <dd><code>{currentRecord.ml.model}</code></dd>
              <dt>Probability:</dt>
              <dd>{(currentRecord.ml.malicious_probability * 100).toFixed(1)}%</dd>
              <dt>Calibration:</dt>
              <dd>{currentRecord.ml.calibrated ? 'Calibrated' : 'uncalibrated'}</dd>
            </dl>
          </div>
        ) : (
          <p className="helper-text">
            Model score: Not connected. The rule-based verdict above is what this scan used.
          </p>
        )}
      </section>
    </div>
  );
}

// -------------------------------------------------------------
// 5. SCANNER: Report Page (/scanner/report)
// -------------------------------------------------------------
export function ScannerReportPage() {
  const { currentRecord } = useWorkbenchStore();
  const [format, setFormat] = useState<'json' | 'markdown'>('markdown');

  if (!currentRecord) {
    return (
      <div className="page">
        <PageHeader section="Package Scanner" title="Report" description="Export scan report" />
        <section className="panel">
          <p className="helper-text">No package has been scanned yet.</p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <NavLink className="button button--primary" to="/scanner/scan">
              Scan a package
            </NavLink>
          </div>
        </section>
      </div>
    );
  }

  const jsonContent = JSON.stringify(currentRecord, null, 2);

  const generateMarkdown = (record: ScanRecord): string => {
    const outcomeStr = formatVerdictOutcome(record.verdict.outcome);
    let md = `# SPIDER Inspection Report: ${record.target?.name ?? record.scan_id}\n\n`;
    md += `- **Scan ID**: ${record.scan_id}\n`;
    md += `- **Verdict**: ${outcomeStr}\n`;
    md += `- **Reasons**: ${record.verdict.reasons.join(', ') || 'None'}\n`;
    md += `- **Review Recommended**: ${record.verdict.review_recommended ? 'Yes' : 'No'}\n`;
    md += `- **Files inspected**: ${record.inventory.files_inspected ?? 0} / ${record.inventory.files_total ?? 0}\n`;
    md += `- **Python files**: ${record.inventory.python_files ?? 0}\n\n`;

    md += `## Findings (${record.findings.length})\n\n`;
    if (record.findings.length === 0) {
      md += `No findings in the inspected files.\n\n`;
    } else {
      md += `| Severity | Indicator | Category | File:Line | Explanation |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- |\n`;
      record.findings.forEach((f) => {
        const line = f.span?.start_line ? `:${f.span.start_line}` : '';
        md += `| ${escapeMarkdown(f.severity)} | ${escapeMarkdown(f.indicator)} | ${escapeMarkdown(f.category)} | ${escapeMarkdown(f.file + line)} | ${escapeMarkdown(f.explanation || '')} |\n`;
      });
      md += `\n`;
    }

    md += `## Limitations\n\n`;
    if (record.verdict.limitations && record.verdict.limitations.length > 0) {
      record.verdict.limitations.forEach((lim) => {
        md += `- ${lim}\n`;
      });
    } else {
      md += `- Static inspection only.\n`;
    }
    md += `\n---\n_${DISCLAIMER}_\n`;
    return md;
  };

  const mdContent = generateMarkdown(currentRecord);
  const activeContent = format === 'json' ? jsonContent : mdContent;
  const fileName = `spider-report-${currentRecord.scan_id}.${format === 'json' ? 'json' : 'md'}`;

  const handleDownload = () => {
    const blob = new Blob([activeContent], { type: format === 'json' ? 'application/json' : 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page">
      <PageHeader
        section="Package Scanner"
        title="Report"
        description={`Export record for ${currentRecord.target?.name ?? currentRecord.scan_id}`}
      />

      <section className="panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
          <SectionHeading title="Report preview" />
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <button
              type="button"
              className={`button ${format === 'markdown' ? 'button--primary' : 'button--secondary'}`}
              onClick={() => setFormat('markdown')}
            >
              Markdown
            </button>
            <button
              type="button"
              className={`button ${format === 'json' ? 'button--primary' : 'button--secondary'}`}
              onClick={() => setFormat('json')}
            >
              JSON
            </button>
            <button type="button" className="button button--primary" onClick={handleDownload}>
              Download {format.toUpperCase()}
            </button>
          </div>
        </div>

        <pre style={{
          padding: 'var(--space-4)',
          background: 'var(--color-surface-raised)',
          borderRadius: 'var(--radius-sm)',
          overflowX: 'auto',
          maxHeight: '400px',
          fontSize: 'var(--text-sm)',
        }}>
          {activeContent}
        </pre>
      </section>

      <p className="helper-text" style={{ marginTop: 'var(--space-6)' }}>
        {DISCLAIMER}
      </p>
    </div>
  );
}

// -------------------------------------------------------------
// 6. HUNTER: Scan Page (/hunter/scan)
// -------------------------------------------------------------
export function HunterScanPage() {
  const navigate = useNavigate();
  const {
    hunterRoots,
    selectedRoots,
    customRoot,
    loadHunterRoots,
    toggleRootSelection,
    setCustomRoot,
    startHunt,
    isHunting,
    huntProgress,
    huntError,
  } = useWorkbenchStore();

  useEffect(() => {
    void loadHunterRoots();
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const rootsToScan = [...selectedRoots];
    if (customRoot.trim()) {
      rootsToScan.push(customRoot.trim());
    }
    const result = await startHunt(rootsToScan);
    if (result) {
      navigate('/hunter/report');
    }
  };

  return (
    <div className="page">
      <PageHeader
        section="Environment Hunter"
        title="Scan environment"
        description="Scan this computer's Python environments"
      />

      <section className="panel" style={{ maxWidth: '640px' }}>
        <SectionHeading title="Select inspection roots" />

        <form onSubmit={handleSubmit}>
          <p className="helper-text" style={{ marginBottom: 'var(--space-3)' }}>
            Choose site-packages and environment paths to check for installed startup hooks and anomalies:
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
            {hunterRoots.map((root) => (
              <label key={root} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={selectedRoots.includes(root)}
                  disabled={isHunting}
                  onChange={() => toggleRootSelection(root)}
                />
                <code>{root}</code>
              </label>
            ))}
          </div>

          <div style={{ marginBottom: 'var(--space-4)' }}>
            <label htmlFor="custom-root">Add a site-packages path</label>
            <input
              id="custom-root"
              type="text"
              placeholder="/custom/site-packages or C:\custom\site-packages"
              value={customRoot}
              disabled={isHunting}
              onChange={(e) => setCustomRoot(e.target.value)}
            />
          </div>

          {huntError && (
            <p className="notice notice--amber" role="alert" style={{ marginBottom: 'var(--space-4)' }}>
              {huntError}
            </p>
          )}

          {isHunting && (
            <div style={{ textAlign: 'center', marginBottom: 'var(--space-4)' }}>
              <div className="hunter-radar" aria-hidden="true">
                <div className="hunter-radar__sweep" />
              </div>
              <p className="helper-text" role="status">
                Hunting in progress... ({huntProgress?.stage ?? 'inspecting'})
              </p>
            </div>
          )}

          <button
            type="submit"
            className="button button--primary"
            disabled={isHunting || (selectedRoots.length === 0 && !customRoot.trim())}
          >
            {isHunting ? 'Inspecting environments...' : 'Scan this computer\'s Python environments'}
          </button>
        </form>
      </section>

      <HunterChecks />
    </div>
  );
}

// -------------------------------------------------------------
// 7. HUNTER: Report Page (/hunter/report)
// -------------------------------------------------------------
export function HunterReportPage() {
  const { lastHuntResult, startHunt, isHunting } = useWorkbenchStore();
  const [showAllowlisted, setShowAllowlisted] = useState(false);

  useEffect(() => {
    if (!lastHuntResult) {
      void startHunt();
    }
  }, []);

  if (!lastHuntResult) {
    return (
      <div className="page">
        <PageHeader section="Environment Hunter" title="Report" description="Loading environment report..." />
      </div>
    );
  }

  const items = lastHuntResult.items || [];
  const visibleItems = items.filter((item) => showAllowlisted || !item.allowlisted);
  const allowlistedCount = items.filter((item) => item.allowlisted).length;

  const high = visibleItems.filter((i) => i.severity.toUpperCase() === 'HIGH');
  const medium = visibleItems.filter((i) => i.severity.toUpperCase() === 'MEDIUM');
  const low = visibleItems.filter((i) => i.severity.toUpperCase() === 'LOW');
  const other = visibleItems.filter((i) => !['HIGH', 'MEDIUM', 'LOW'].includes(i.severity.toUpperCase()));

  const renderHunterGroup = (title: string, list: HuntItem[]) => {
    if (list.length === 0) return null;
    return (
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <h3>{title} ({list.length})</h3>
        <div className="table-scroll">
          <table className="hunt-table">
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Reason</th>
                <th>Path</th>
                <th>Evidence snippet</th>
                <th>Priority</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {list.map((it, idx) => (
                <tr key={idx}>
                  <td><code>{it.artifact}</code></td>
                  <td>{it.reason}</td>
                  <td><code className="muted">{it.path || '—'}</code></td>
                  <td>{it.evidence_snippet ? <code>{it.evidence_snippet}</code> : '—'}</td>
                  <td>{it.priority ?? '—'}</td>
                  <td>
                    <button
                      type="button"
                      className="button button--secondary"
                      disabled
                      title="Needs the local backend"
                      style={{ padding: '2px 8px', fontSize: 'var(--text-sm)' }}
                    >
                      Allow this file
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  return (
    <div className="page">
      <PageHeader
        section="Environment Hunter"
        title="Report"
        description={`Report for Hunt ID: ${lastHuntResult.hunt_id}`}
      />

      {/* Header card */}
      <section className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <SectionHeading title="Environment run summary" />
        <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
          <dt>Timestamp:</dt>
          <dd>{lastHuntResult.created_at}</dd>
          <dt>Environments inspected:</dt>
          <dd>{lastHuntResult.roots.join(', ')}</dd>
          <dt>Distributions count:</dt>
          <dd><strong><AnimatedNumber value={lastHuntResult.distributions_count} /></strong></dd>
        </dl>
      </section>

      {/* Findings */}
      <section className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
          <SectionHeading title="Installed environment findings" />
          {allowlistedCount > 0 && (
            <button
              type="button"
              className="button button--secondary"
              onClick={() => setShowAllowlisted(!showAllowlisted)}
            >
              {showAllowlisted ? 'Hide allowlisted' : `Show ${allowlistedCount} allowlisted`}
            </button>
          )}
        </div>

        {visibleItems.length === 0 ? (
          <p className="helper-text">No findings in the inspected environments.</p>
        ) : (
          <>
            {renderHunterGroup('High severity', high)}
            {renderHunterGroup('Medium severity', medium)}
            {renderHunterGroup('Low severity', low)}
            {renderHunterGroup('Other findings', other)}
          </>
        )}
      </section>

      {/* Stage 3: Hunter Node Map of inspected roots */}
      <HunterNodeMap huntResult={lastHuntResult} />

      {/* Coverage & Limitations */}
      <details className="panel">
        <summary><strong>Coverage & limitations</strong></summary>
        <div style={{ marginTop: 'var(--space-3)' }}>
          <dl className="readout" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-2)' }}>
            <dt>Skipped too large:</dt>
            <dd>{lastHuntResult.coverage?.counts?.skipped_too_large ?? 0}</dd>
            <dt>Missing in RECORD:</dt>
            <dd>{lastHuntResult.coverage?.counts?.missing_in_RECORD ?? 0}</dd>
            <dt>Inspection timed out:</dt>
            <dd>{lastHuntResult.coverage?.counts?.inspection_timed_out ?? 0}</dd>
            <dt>File list unavailable:</dt>
            <dd>{lastHuntResult.coverage?.counts?.file_list_unavailable ?? 0}</dd>
            <dt>Entry-point ownership unknown:</dt>
            <dd>{lastHuntResult.coverage?.counts?.entry_point_unknown ?? 0}</dd>
          </dl>

          {lastHuntResult.limitations && lastHuntResult.limitations.length > 0 && (
            <div style={{ marginTop: 'var(--space-4)' }}>
              <h4>Limitations:</h4>
              <ul className="limitation-list">
                {lastHuntResult.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </details>

      <p className="helper-text" style={{ marginTop: 'var(--space-6)' }}>
        Static analysis only. 'None detected in this scan' does not mean the package is safe.
      </p>
    </div>
  );
}

// -------------------------------------------------------------
// 8. HISTORY: History Page (/history/history)
// -------------------------------------------------------------
export function HistoryListPage() {
  const navigate = useNavigate();
  const { history, loadHistory, historyLoading, historyError, loadScanRecord } = useWorkbenchStore();

  useEffect(() => {
    void loadHistory();
  }, []);

  const handleOpenScan = async (scanId: string) => {
    const record = await loadScanRecord(scanId);
    if (record) {
      navigate(`/scanner/result?id=${encodeURIComponent(scanId)}`);
    } else {
      navigate(`/scanner/result?id=${encodeURIComponent(scanId)}`);
    }
  };

  return (
    <div className="page">
      <PageHeader
        section="History and Reports"
        title="Scan history"
        description="Every scan and every export in one place."
      />

      <section className="panel">
        <SectionHeading title="Recorded scans" />

        {historyLoading && <p className="helper-text">Loading history...</p>}
        {historyError && <p className="notice notice--amber">{historyError}</p>}

        {!historyLoading && history.length === 0 && (
          <p className="helper-text">No scans saved in history yet.</p>
        )}

        {history.length > 0 && (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Package / Archive</th>
                  <th>Version</th>
                  <th>Verdict</th>
                  <th>Timestamp</th>
                  <th>Findings</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {history.map((record) => (
                  <tr key={record.scan_id}>
                    <td>
                      <strong>{record.target?.name ?? record.scan_id}</strong>
                    </td>
                    <td>{record.target?.version ?? '—'}</td>
                    <td>
                      <span className={`badge badge--${record.verdict.outcome === 'suspicious' ? 'amber' : 'neutral'}`}>
                        {formatVerdictOutcome(record.verdict.outcome)}
                      </span>
                    </td>
                    <td className="muted">{record.created_at ?? '—'}</td>
                    <td>{record.findings.length}</td>
                    <td>
                      <button
                        type="button"
                        className="button button--secondary"
                        style={{ padding: '2px 8px', fontSize: 'var(--text-sm)' }}
                        onClick={() => handleOpenScan(record.scan_id)}
                      >
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <HistoryTips />
    </div>
  );
}

// -------------------------------------------------------------
// 9. HISTORY: Reports Page (/history/reports)
// -------------------------------------------------------------
export function HistoryReportsPage() {
  const { history, loadHistory, currentRecord, loadScanRecord } = useWorkbenchStore();
  const [selectedId, setSelectedId] = useState<string>(currentRecord?.scan_id ?? '');

  useEffect(() => {
    void loadHistory();
  }, []);

  useEffect(() => {
    if (history.length > 0 && !selectedId) {
      setSelectedId(history[0].scan_id);
      void loadScanRecord(history[0].scan_id);
    }
  }, [history]);

  const handleSelect = (id: string) => {
    setSelectedId(id);
    void loadScanRecord(id);
  };

  return (
    <div className="page">
      <PageHeader
        section="History and Reports"
        title="Reports"
        description="Pick a saved scan to preview or export."
      />

      <section className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <SectionHeading title="Select saved scan" />
        {history.length === 0 ? (
          <p className="helper-text">No saved scans available to export.</p>
        ) : (
          <div style={{ maxWidth: '400px' }}>
            <label htmlFor="history-scan-select">Saved scans:</label>
            <select
              id="history-scan-select"
              value={selectedId}
              onChange={(e) => handleSelect(e.target.value)}
            >
              {history.map((h) => (
                <option key={h.scan_id} value={h.scan_id}>
                  {h.target?.name ?? h.scan_id} ({formatVerdictOutcome(h.verdict.outcome)})
                </option>
              ))}
            </select>
          </div>
        )}
      </section>

      {/* Re-use scanner report view for preview/download */}
      {currentRecord && <ScannerReportPage />}
    </div>
  );
}

// -------------------------------------------------------------
// 10. SETTINGS: Settings Page (/settings)
// -------------------------------------------------------------
export function SettingsPage() {
  const { reducedMotion, setReducedMotion, quality, setQuality } = useWorkbenchStore();

  return (
    <div className="page">
      <PageHeader
        section="Preferences"
        title="Settings"
        description="Theme and motion preferences"
      />

      <section className="panel" style={{ maxWidth: '480px' }}>
        <SectionHeading title="Motion & Artwork" />

        <div style={{ marginBottom: 'var(--space-4)' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={reducedMotion}
              onChange={(e) => setReducedMotion(e.target.checked)}
            />
            Reduce interface animations and canvas motion
          </label>
        </div>

        <div>
          <label htmlFor="scene-quality">Canvas scene quality</label>
          <select
            id="scene-quality"
            value={quality}
            onChange={(e) => setQuality(e.target.value as 'auto' | 'high' | 'medium' | 'low' | 'off')}
          >
            <option value="auto">Auto</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="off">Off</option>
          </select>
        </div>
      </section>
    </div>
  );
}
