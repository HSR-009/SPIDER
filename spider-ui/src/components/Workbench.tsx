import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { environmentFor } from "../app/environments";
import { useWorkbenchStore } from "../state/workbench";
import { SpiderMark } from "./SpiderMark";
import { RouteLoader } from "./RouteLoader";
import { isMockBackend } from "../backend";

export type IconName =
  | "overview"
  | "scanner"
  | "history"
  | "workspace"
  | "evidence"
  | "features"
  | "models"
  | "explain"
  | "datasets"
  | "lab"
  | "shield"
  | "environment"
  | "findings"
  | "reports"
  | "settings"
  | "search"
  | "arrow"
  | "close"
  | "menu";

export type Tone = "amber" | "cyan" | "violet" | "neutral" | "danger" | "ok" | "warning";

export function Icon({ name, className = "" }: { name: IconName; className?: string }) {
  const paths: Record<IconName, ReactNode> = {
    overview: <><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z" /></>,
    scanner: <><path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M3 12h18M8 8h8m-8 8h8" /></>,
    history: <><path d="M3 11a9 9 0 1 1 2 7M3 4v7h7m2-5v6l4 3" /></>,
    workspace: <><path d="M3 5h18v15H3zM3 10h18M9 10v10M7 5V3m10 2V3" /></>,
    evidence: <><path d="M5 3h9l5 5v13H5zM14 3v6h5M8 13h8m-8 4h5" /></>,
    features: <><path d="M4 6h16M4 12h16M4 18h16M8 3v6m8 0v6m-6 0v6" /></>,
    models: <><path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5" /></>,
    explain: <><circle cx="5" cy="12" r="2" /><circle cx="19" cy="5" r="2" /><circle cx="19" cy="19" r="2" /><path d="m7 11 10-5M7 13l10 5" /></>,
    datasets: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0" /></>,
    lab: <><path d="M9 3h6m-5 0v7L4 20h16l-6-10V3M7 15h10" /></>,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3ZM9 12l2 2 4-4" /></>,
    environment: <><path d="M3 4h18v13H3zM8 21h8m-4-4v4M7 8l3 3-3 3m6 0h4" /></>,
    findings: <><path d="m12 3 10 18H2L12 3Zm0 6v5m0 3v1" /></>,
    reports: <><path d="M5 3h10l4 4v14H5zM9 17v-3m3 3v-6m3 6V9" /></>,
    settings: <><path d="M3 6h18M3 18h18" /><circle cx="8" cy="6" r="3" /><circle cx="16" cy="18" r="3" /></>,
    search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 5 5" /></>,
    arrow: <><path d="M4 12h16m-6-6 6 6-6 6" /></>,
    close: <><path d="m6 6 12 12M18 6 6 18" /></>,
    menu: <><path d="M4 6h16M4 12h16M4 18h16" /></>,
  };
  return (
    <svg
      className={`icon ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

export function PageHeader({
  section,
  title,
  description,
  action,
}: {
  section: string;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{section}</p>
        <h1>{title}</h1>
        {description && <p className="page-header__desc">{description}</p>}
      </div>
      {action && <div className="page-header__action">{action}</div>}
    </header>
  );
}

export function SectionHeading({
  title,
  aside,
}: {
  title: string;
  aside?: ReactNode;
}) {
  return (
    <div className="section-heading">
      <h2>{title}</h2>
      {aside && <div className="section-heading__aside">{aside}</div>}
    </div>
  );
}

export function RouteLink({
  to,
  children,
  secondary = false,
}: {
  to: string;
  children: ReactNode;
  secondary?: boolean;
}) {
  return (
    <NavLink
      className={`button ${secondary ? "button--secondary" : "button--primary"}`}
      to={to}
    >
      {children}
    </NavLink>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      {children && <div className="empty-state__body">{children}</div>}
      {action && <div className="empty-state__action">{action}</div>}
    </div>
  );
}

export function NotFoundPage() {
  return (
    <div className="page">
      <EmptyState
        title="Page not found"
        action={<RouteLink to="/hub">Return to Tool Hub</RouteLink>}
      >
        <p>The requested page does not exist or has been relocated.</p>
      </EmptyState>
    </div>
  );
}

/** Workbench Layout with per-environment sidebar */
export function Workbench({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const currentEnv = environmentFor(pathname);

  // Transition loader state
  const prevPathRef = useRef(pathname);
  const [loaderDestination, setLoaderDestination] = useState<string | null>(null);

  useEffect(() => {
    const prev = prevPathRef.current;
    prevPathRef.current = pathname;

    // Check transition: Hub -> Environment OR Environment -> Hub
    if (prev === "/hub" && pathname !== "/" && pathname !== "/hub") {
      const destName = currentEnv?.name ?? "Tool";
      setLoaderDestination(destName);
    } else if (prev !== "/" && prev !== "/hub" && pathname === "/hub") {
      setLoaderDestination("Tool Hub");
    }
  }, [pathname, currentEnv]);

  // Close drawer on path navigation
  useEffect(() => {
    setDrawerOpen(false);
  }, [pathname]);

  const isLandingPage = pathname === "/";
  const isHub = pathname === "/hub";

  return (
    <div className={`workbench${isLandingPage ? " workbench--experience" : ""}${isHub ? " workbench--hub" : ""}`}>
      <a href="#main" className="skip-link">Skip to main content</a>

      {/* Route transition loader overlay */}
      {loaderDestination && !isLandingPage && (
        <RouteLoader
          destinationName={loaderDestination}
          onFinish={() => setLoaderDestination(null)}
        />
      )}

      {/* Mock backend ribbon */}
      {isMockBackend && (
      <div
        style={{
          position: "fixed",
          bottom: "var(--space-2)",
          right: "var(--space-2)",
          background: "var(--color-surface-raised)",
          border: "1px solid var(--color-border)",
          padding: "var(--space-1) var(--space-3)",
          borderRadius: "var(--radius-sm)",
          fontSize: "var(--text-xs)",
          zIndex: 100,
          opacity: 0.85,
        }}
      >
        Sample data (mock backend)
      </div>
      )}

      {/* Drawer toggle for narrow screens */}
      {!isLandingPage && !isHub && (
        <button
          type="button"
          className="icon-button mobile-menu"
          aria-label={drawerOpen ? "Close menu" : "Open menu"}
          aria-expanded={drawerOpen}
          onClick={() => setDrawerOpen(!drawerOpen)}
          style={{
            position: "fixed",
            top: "var(--space-2)",
            right: "var(--space-2)",
            zIndex: 40,
          }}
        >
          <Icon name={drawerOpen ? "close" : "menu"} />
        </button>
      )}

      {/* Environment Sidebar (shown ONLY when not on landing page and not on hub) */}
      {!isLandingPage && !isHub && (
        <aside className={`sidebar ${drawerOpen ? "sidebar--open" : ""}`} aria-label="Main Navigation">
          <NavLink to="/hub" className="brand" aria-label="SPIDER tool hub">
            <SpiderMark className="brand__mark" />
            <span>
              SPIDER
              <small>{currentEnv?.name ?? "Workbench"}</small>
            </span>
          </NavLink>

          <nav className="primary-nav" aria-label={`${currentEnv?.name ?? "Tool"} navigation`}>
            <NavLink to="/hub" className="env-back">
              ← All tools
            </NavLink>

            {currentEnv && (
              <section className="nav-group" aria-label={currentEnv.name}>
                <h2>{currentEnv.name}</h2>
                <p className="env-tagline">{currentEnv.tagline}</p>
                <ul>
                  {currentEnv.items.map((item) => (
                    <li key={item.path}>
                      <NavLink
                        to={item.path}
                        end
                        className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
                      >
                        <Icon name={item.icon} />
                        <span className="nav-link__copy">
                          <span>{item.label}</span>
                        </span>
                        <span className="nav-link__indicator" aria-hidden="true" />
                      </NavLink>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </nav>

          <div className="sidebar__foot">
            <NavLink to="/settings">
              Settings <Icon name="arrow" />
            </NavLink>
            <p>Static analysis only. Not a safety certificate.</p>
          </div>
        </aside>
      )}

      {/* Shell Body: wraps content and gives margin-left when sidebar is present */}
      <div className="shell-body">
        {isLandingPage && (
          <header className="topbar">
            <NavLink to="/" className="experience-brand" aria-label="SPIDER overview">
              <SpiderMark compact />
              <span>SPIDER</span>
            </NavLink>
            <span className="experience-brand__divider" aria-hidden="true" />
            <span className="experience-brand__desc">Static investigation workbench</span>
            <nav className="experience-masthead__links" aria-label="Quick navigation">
              <NavLink to="/hub">Enter SPIDER</NavLink>
            </nav>
            <span className="experience-status-chip" data-state="connected">
              <span className="experience-status-dot" aria-hidden="true" />
              Connected
            </span>
          </header>
        )}
        <main
          id="main"
          className="main-content"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
