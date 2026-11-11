import { NavLink } from 'react-router-dom';
import { Badge, SectionHeading } from './Workbench';

/** Static explanatory panels. Pure copy; no backend calls. */

export function VerdictKey() {
  return (
    <section className="panel">
      <SectionHeading title="The three verdicts" />
      <p className="helper-text">SPIDER never says a package is safe. Every scan ends in one of these.</p>
      <ul className="info-list">
        <li>
          <Badge tone="amber">Suspicious</Badge>
          <p>A strong combination of signals was found. The evidence lines are shown so a person can decide. It is a reason to investigate, not proof of intent.</p>
        </li>
        <li>
          <Badge tone="neutral">None detected in this scan</Badge>
          <p>No strong signal in the code that was inspected. This is not a safety claim. A “review recommended” note may still be attached.</p>
        </li>
        <li>
          <Badge tone="neutral">Unable to assess</Badge>
          <p>Too much of the package could not be inspected (native binaries, files that fail to parse, size limits). The scan says so instead of guessing.</p>
        </li>
      </ul>
    </section>
  );
}

export function ScanSteps() {
  return (
    <div className="info-grid">
      <section className="panel">
        <SectionHeading title="What happens when you scan" />
        <ol className="info-steps">
          <li><strong>Safe extraction.</strong> The archive is unpacked with path and size checks. Nothing is imported or executed.</li>
          <li><strong>Static analysis.</strong> Python files are parsed into an AST and checked against the rule set.</li>
          <li><strong>Verdict policy.</strong> Findings are combined into one of three verdicts, with coverage limits recorded.</li>
          <li><strong>A saved record.</strong> The scan is stored, so you can reopen it from History and export it.</li>
        </ol>
      </section>
      <section className="panel">
        <SectionHeading title="What you get back" />
        <ul className="info-list info-list--plain">
          <li><strong>Result</strong><p>The verdict, counts and the files that were inspected.</p></li>
          <li><strong>Evidence</strong><p>Each finding with its rule, file and line, so you can check it yourself.</p></li>
          <li><strong>Score</strong><p>Model score status. Shown only when a model output exists; it is never invented.</p></li>
          <li><strong>Report</strong><p>The whole record as JSON or Markdown.</p></li>
        </ul>
      </section>
      <section className="panel">
        <SectionHeading title="Accepted input" />
        <ul className="limitation-list">
          <li>An archive: <code>.whl</code>, <code>.tar.gz</code> or <code>.zip</code>.</li>
          <li>A folder path to an unpacked package.</li>
          <li>From the command line, a release such as <code>name==1.0.0</code> (needs network).</li>
        </ul>
        <p className="helper-text">Compiled extensions (<code>.so</code>, <code>.pyd</code>) are not inspected.</p>
      </section>
    </div>
  );
}

export function HunterChecks() {
  return (
    <div className="info-grid">
      <section className="panel">
        <SectionHeading title="What the Hunter looks for" />
        <ul className="info-list info-list--plain">
          <li><strong>.pth files</strong><p>Lines in <code>.pth</code> files can run code every time Python starts.</p></li>
          <li><strong>sitecustomize and usercustomize</strong><p>Modules Python imports automatically at start-up.</p></li>
          <li><strong>Entry points</strong><p>Console scripts and plugins registered by installed packages.</p></li>
          <li><strong>RECORD tampering</strong><p>Installed files that no longer match the list the installer recorded.</p></li>
        </ul>
      </section>
      <section className="panel">
        <SectionHeading title="How a run works" />
        <ol className="info-steps">
          <li><strong>Pick roots.</strong> Choose the site-packages folders to inspect, or add your own.</li>
          <li><strong>Scan.</strong> Startup hooks and installed files are read. Nothing is run or modified.</li>
          <li><strong>Read the report.</strong> Findings come with the coverage of what was and was not reachable.</li>
        </ol>
        <p className="helper-text">Tested on planted cases and one real environment run. Treat a clean report as “nothing found here”, not as a clean bill of health.</p>
      </section>
    </div>
  );
}

const SIGNALS: Array<[string, string, string]> = [
  ['Dynamic execution', 'exec(), eval(), compile() on built strings', 'Hides what code will run until it runs.'],
  ['Encoded payloads', 'base64 or hex blobs that are decoded then used', 'Keeps the real behaviour out of plain sight.'],
  ['Network access', 'requests to a remote host from setup or import', 'Downloads a second stage or sends data out.'],
  ['Process launching', 'subprocess, os.system', 'Runs shell commands on the machine.'],
  ['Install-time hooks', 'custom setup.py commands, build overrides', 'Runs before the user imports anything.'],
  ['Startup persistence', '.pth lines, sitecustomize', 'Survives restarts and runs on every Python start.'],
];

export function SignalGlossary() {
  return (
    <section className="panel panel--table">
      <div style={{ padding: 'var(--space-6) var(--space-6) 0' }}>
        <SectionHeading title="Signals worth a second look" />
        <p className="helper-text" style={{ marginBottom: 'var(--space-4)' }}>
          Each of these is common in honest software too. SPIDER weighs combinations, which is why a single hit is only a reason to read the code.
        </p>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Signal</th><th>Looks like</th><th>Why attackers use it</th></tr></thead>
          <tbody>
            {SIGNALS.map(([a, b, c]) => (
              <tr key={a}><td><strong>{a}</strong></td><td>{b}</td><td>{c}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function LearnLimits() {
  return (
    <div className="info-grid">
      <section className="panel">
        <SectionHeading title="Why static analysis misses things" />
        <ul className="limitation-list">
          <li>Behaviour that depends on runtime state is out of reach.</li>
          <li>Code can be disguised. In SPIDER’s own 12-sample evasion test, only 1 was called suspicious.</li>
          <li>Native compiled code and prose aimed at AI agents are not analysed.</li>
          <li>Package-wide rules can join unrelated files and raise false alarms.</li>
        </ul>
      </section>
      <section className="panel">
        <SectionHeading title="What to do with a verdict" />
        <ul className="limitation-list">
          <li><strong>Suspicious:</strong> read the evidence lines, then decide.</li>
          <li><strong>None detected:</strong> still apply normal care: check the name, the maintainer and the release history.</li>
          <li><strong>Unable to assess:</strong> treat as unknown and inspect by other means.</li>
        </ul>
        <div style={{ marginTop: 'var(--space-4)', display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <NavLink className="button button--secondary" to="/hunter/scan">Open Environment Hunter</NavLink>
          <NavLink className="button button--secondary" to="/research">See measured results</NavLink>
        </div>
      </section>
    </div>
  );
}

export function ExtensionExtras() {
  return (
    <div className="info-grid">
      <section className="panel">
        <SectionHeading title="Why check before installing" />
        <p>
          Installing is the moment code first runs. A check at that point catches a bad package before it reaches the machine, which is cheaper than finding it afterwards with the Environment Hunter.
        </p>
      </section>
      <section className="panel">
        <SectionHeading title="Until it ships" />
        <ul className="limitation-list">
          <li>Download the archive and scan it in the Package Scanner.</li>
          <li>Run <code>python -m spider scan name==version</code> from the command line.</li>
          <li>Use the Environment Hunter for what is already installed.</li>
        </ul>
        <div style={{ marginTop: 'var(--space-4)' }}>
          <NavLink className="button button--secondary" to="/scanner/scan">Open Package Scanner</NavLink>
        </div>
      </section>
    </div>
  );
}

export function HistoryTips() {
  return (
    <section className="panel">
      <SectionHeading title="About saved scans" />
      <ul className="limitation-list">
        <li>Each scan is stored as one record that can be reopened by its ID.</li>
        <li>Open a row to see its verdict, evidence and report, exactly as first produced.</li>
        <li>Use the Reports tab to export a record as JSON or Markdown.</li>
        <li>Records contain file names and code excerpts. Check before sharing them.</li>
      </ul>
    </section>
  );
}

export function ResultsReading() {
  return (
    <section className="panel">
      <SectionHeading title="How to read these numbers" />
      <ul className="limitation-list">
        <li><strong>Signal, not accuracy.</strong> The corpus rates show how often a verdict fires, not how often it is right.</li>
        <li><strong>Size confound.</strong> Malicious packages are much smaller, and size alone separates the classes.</li>
        <li><strong>False positives are small-sample.</strong> They describe 100 obscure packages, not PyPI in general.</li>
        <li><strong>Reproducible.</strong> Every figure names its source file in the repository.</li>
      </ul>
    </section>
  );
}
