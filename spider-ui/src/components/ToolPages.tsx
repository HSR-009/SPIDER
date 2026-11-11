import { NavLink } from 'react-router-dom';
import { Badge, PageHeader, SectionHeading } from './Workbench';
import { ExtensionExtras, SignalGlossary, LearnLimits } from './Guidance';

export function ExtensionPage() {
  return (
    <div className="page">
      <PageHeader
        section="SPIDER Extension"
        title="Check a package before you install it."
        description="A lightweight check on packages before installation."
        action={<Badge tone="amber">Coming soon</Badge>}
      />

      <section className="panel">
        <SectionHeading title="Download" />
        <button type="button" className="button button--secondary" disabled>
          Download
        </button>
        <span style={{ marginLeft: 'var(--space-3)' }} className="badge badge--amber">Coming soon</span>
        <p className="helper-text" style={{ marginTop: 'var(--space-3)' }}>
          Direct installation check will be supported once client hooks are released.
        </p>
      </section>

      <section className="panel">
        <SectionHeading title="How it works" />
        <ol className="dm-flow">
          <li>
            <strong>1. Read package name</strong>
            <br />
            <span className="helper-text">Identifies the candidate package before installation starts.</span>
          </li>
          <li>
            <strong>2. Ask SPIDER</strong>
            <br />
            <span className="helper-text">Queries your local SPIDER service for known signals and static rules.</span>
          </li>
          <li>
            <strong>3. Show verdict</strong>
            <br />
            <span className="helper-text">Displays the static verdict before any source is unpacked or installed.</span>
          </li>
        </ol>
      </section>

      <section className="panel">
        <SectionHeading title="Setup" />
        <ul className="limitation-list">
          <li><span className="badge badge--neutral">Planned</span> Browser extension hook for index pages.</li>
          <li><span className="badge badge--neutral">Planned</span> Shell alias wrapper for package managers.</li>
          <li><span className="badge badge--neutral">Planned</span> Local daemon listening on 127.0.0.1.</li>
        </ul>
      </section>

      <section className="panel">
        <SectionHeading title="What it will not do" />
        <ul className="limitation-list">
          <li>Never installs or runs code.</li>
          <li>Never says a package is safe.</li>
        </ul>
      </section>

      <ExtensionExtras />
    </div>
  );
}

export function HowPackagesAttackPage() {
  return (
    <div className="page">
      <PageHeader
        section="Guide"
        title="How malicious packages cause harm"
        description="How a malicious package gets in and what it does."
      />

      <div className="info-grid">
        <section className="panel">
          <SectionHeading title="1. Getting in" />
          <p>
            Attackers publish packages with names very close to popular packages (typosquatting), exploit dependency confusion across public and private feeds, or compromise maintainer accounts with stolen tokens.
          </p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <span className="badge badge--cyan">SPIDER checks this with: Scanner</span>
          </div>
        </section>

        <section className="panel">
          <SectionHeading title="2. Install time" />
          <p>
            Custom <code>setup.py</code> commands, build hook overrides, or drop-in <code>.pth</code> files run code immediately when a package is installed, before the user ever writes an <code>import</code> statement.
          </p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <span className="badge badge--cyan">SPIDER checks this with: Scanner / Hunter</span>
          </div>
        </section>

        <section className="panel">
          <SectionHeading title="3. Import/run time" />
          <p>
            Code executed during module import or runtime often conceals its behavior through hidden <code>exec()</code>, nested base64 decoding, string de-obfuscation, or dynamic <code>getattr()</code> calls.
          </p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <span className="badge badge--cyan">SPIDER checks this with: Scanner</span>
          </div>
        </section>

        <section className="panel">
          <SectionHeading title="4. What it takes & why it is hard to catch" />
          <p>
            Attackers exfiltrate environment variables, API tokens, and SSH keys. These packages are hard to catch because they are often tiny, use delayed execution triggers, or hide in benign-looking utility scripts.
          </p>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <span className="badge badge--cyan">SPIDER checks this with: Planned</span>
          </div>
        </section>
      </div>

      <SignalGlossary />
      <LearnLimits />

      <div style={{ marginTop: 'var(--space-2)' }}>
        <NavLink className="button button--primary" to="/scanner/scan">
          Open Package Scanner
        </NavLink>
      </div>
    </div>
  );
}
