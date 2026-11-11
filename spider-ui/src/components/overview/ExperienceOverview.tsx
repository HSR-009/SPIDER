import { Fragment, Suspense, lazy, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { RouteLink } from '../Workbench';
import { ExperienceArtwork } from './ExperienceArtwork';
import { splitCharacters, useChapterScroll } from './useChapterScroll';
import { useExperienceMotion } from './useExperienceMotion';
import { useWorkbenchStore } from '../../state/workbench';

const LazyWelcomeScene = lazy(() => import('./WelcomeScene'));

interface Chapter {
  id: string;
  rail: string;
  title: [string, string];
  text: string;
  cta: { to: string; label: string };
  secondary?: { to: string; label: string };
}

const chapters: Chapter[] = [
  {
    id: 'overview',
    rail: 'Overview',
    title: ['Inspect the code.', 'Understand the evidence.'],
    text: 'A local workbench for static package investigation. Every conclusion is kept in context, from archive to evidence.',
    cta: { to: '/hub', label: 'Choose a tool' },
    secondary: { to: '/learn', label: 'How it works' },
  },
  {
    id: 'method',
    rail: 'Method',
    title: ['From archive', 'to understanding.'],
    text: 'Inspect, investigate, export — three deliberate steps, each one leaving an exact, reviewable trail.',
    cta: { to: '/hub', label: 'Choose a tool' },
    secondary: { to: '/learn', label: 'How it works' },
  },
  {
    id: 'evidence',
    rail: 'Evidence',
    title: ['Follow a finding', 'to its source.'],
    text: 'Recorded excerpts, provenance and coverage read side by side. Snippets stay inert; nothing executes.',
    cta: { to: '/hub', label: 'Choose a tool' },
    secondary: { to: '/learn', label: 'How it works' },
  },
  {
    id: 'records',
    rail: 'Records',
    title: ['Every record', 'keeps its receipt.'],
    text: 'Completed, incomplete or failed — persisted investigations reopen by their exact ID, never a substitute.',
    cta: { to: '/hub', label: 'Choose a tool' },
    secondary: { to: '/learn', label: 'How it works' },
  },
  {
    id: 'boundaries',
    rail: 'Boundaries',
    title: ['No execution.', 'No assumptions.'],
    text: 'Static analysis only. Absence of findings is never evidence of safety, and missing outputs stay missing.',
    cta: { to: '/hub', label: 'Choose a tool' },
    secondary: { to: '/learn', label: 'How it works' },
  },
  {
    id: 'begin',
    rail: 'Begin',
    title: ['Start with a', 'question.'],
    text: 'Explore tools, scan packages, or inspect environments when you are ready to inspect.',
    cta: { to: '/hub', label: 'Choose a tool' },
    secondary: { to: '/learn', label: 'How it works' },
  },
];

function StageHeadline({ title }: { title: Chapter['title'] }) {
  let charIndex = 0;
  return (
    <h1 className="stage-headline" aria-label={title.join(' ')}>
      {title.map((line) => (
        <span key={line} className="stage-line" aria-hidden="true">
          {line.split(' ').map((word, wordIndex) => {
            const wordStart = charIndex;
            charIndex += word.length + 1;
            return (
              <Fragment key={`${wordIndex}-${word}`}>
                {wordIndex > 0 && ' '}
                <span className="stage-word">
                  {splitCharacters(word).map((char, charIndexInWord) => (
                    <span
                      key={`${charIndexInWord}-${char}`}
                      className="stage-char"
                      style={{ '--char-i': wordStart + charIndexInWord } as CSSProperties}
                    >
                      {char}
                    </span>
                  ))}
                </span>
              </Fragment>
            );
          })}
        </span>
      ))}
    </h1>
  );
}

export function ExperienceOverview() {
  const reducedMotion = useWorkbenchStore((state) => state.reducedMotion);
  const artwork = true;
  const { heroRef, paused, togglePause, mode } = useExperienceMotion(artwork, reducedMotion);
  const { trackRef, index, blend, progress } = useChapterScroll(chapters.length);
  const pageRef = useRef<HTMLDivElement>(null);
  const chapter = chapters[index];
  const pauseControl = artwork && mode !== 'reduced' && mode !== 'off';

  useEffect(() => {
    const page = pageRef.current;
    if (!page || reducedMotion || typeof IntersectionObserver === 'undefined') return;
    const targets = Array.from(page.querySelectorAll<HTMLElement>('.experience-section, .experience-closing'));
    if (targets.length === 0) return;
    let armed = false;
    const observer = new IntersectionObserver((entries) => {
      if (!armed) {
        armed = true;
        page.classList.add('reveal-armed');
      }
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-revealed');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    targets.forEach((target) => {
      target.classList.add('experience-reveal');
      observer.observe(target);
    });
    return () => {
      observer.disconnect();
      targets.forEach((target) => target.classList.remove('experience-reveal', 'is-revealed'));
      page.classList.remove('reveal-armed');
    };
  }, [reducedMotion]);

  const scrollToChapter = (target: number) => {
    const track = trackRef.current;
    if (!track) return;
    const travel = Math.max(track.offsetHeight - window.innerHeight, 1);
    const top = track.getBoundingClientRect().top + window.scrollY + (travel * target) / chapters.length + 2;
    window.scrollTo({ top, behavior: reducedMotion ? 'auto' : 'smooth' });
  };

  return (
    <div className="experience-page" ref={pageRef}>
      <div className="experience-stage-track" ref={trackRef} style={{ '--chapter-count': chapters.length } as CSSProperties}>
        <section
          className="experience-stage"
          aria-label="SPIDER introduction"
          data-artwork={artwork ? 'true' : 'false'}
          data-chapter={chapter.id}
          data-motion={mode}
          ref={heroRef}
        >
          <div className="stage-frame" aria-hidden="true"><span /><span /><span /><span /></div>
          <nav className="stage-rail" aria-label="Introduction chapters">
            {chapters.map((item, itemIndex) => (
              <button
                key={item.id}
                type="button"
                className="stage-rail__item"
                aria-current={index === itemIndex ? 'true' : undefined}
                onClick={() => scrollToChapter(itemIndex)}
              >
                <span className="stage-rail__tick" aria-hidden="true" />
                <span>{item.rail}</span>
                <span className="stage-rail__num">{String(itemIndex + 1).padStart(2, '0')}</span>
              </button>
            ))}
          </nav>
          <div className="stage-body">
            <div className="stage-copy">
              <p className="stage-kicker" key={`${chapter.id}-kicker`}>
                {`${String(index + 1).padStart(2, '0')} — ${chapter.rail}`}
              </p>
              <StageHeadline key={chapter.id} title={chapter.title} />
              <p key={`${chapter.id}-text`} className="stage-desc">{chapter.text}</p>
              <div className="stage-actions">
                <RouteLink to={chapter.cta.to}>{chapter.cta.label}</RouteLink>
                {chapter.secondary && (
                  <NavLink className="experience-text-link" to={chapter.secondary.to}>
                    {chapter.secondary.label} <span aria-hidden="true">↗</span>
                  </NavLink>
                )}
              </div>
            </div>
            {artwork && (
              <div
                className="stage-art"
                aria-hidden="true"
                style={{ '--chapter-shift': (index + blend).toFixed(3) } as React.CSSProperties}
              >
                {!reducedMotion && mode !== 'off' && (
                  <Suspense fallback={null}>
                    <LazyWelcomeScene paused={paused} />
                  </Suspense>
                )}
                <ExperienceArtwork />
              </div>
            )}
          </div>
          <div className="stage-status">
            <span className="stage-status__scroll">
              {progress > 0.98 ? 'Continue below' : 'Scroll to explore'} <span className="stage-status__arrow">↓</span>
            </span>
            {pauseControl && (
              <button
                type="button"
                className="stage-status__pause"
                aria-pressed={paused}
                onClick={togglePause}
              >
                {paused ? 'Play artwork motion' : 'Pause artwork motion'}
              </button>
            )}
            <span><span className="experience-status-dot" aria-hidden="true" />Local service</span>
          </div>
          <div className="stage-progress">
            <span style={{ width: `${Math.round(((index + blend) / chapters.length) * 100)}%` }} />
          </div>
          <p className="sr-only" role="status">
            {`Landing page chapter ${index + 1} of ${chapters.length}: ${chapter.rail}`}
          </p>
        </section>
      </div>

      <section className="experience-introduction experience-section" aria-labelledby="experience-introduction-title">
        <p className="experience-kicker">The investigation comes first.</p>
        <div>
          <h2 id="experience-introduction-title">Less noise.<br /><span>More context.</span></h2>
          <p>
            Suspicious syntax is a reason to investigate, not a statement of intent. SPIDER brings the source, the static verdict, and the limits of the inspection into the same workspace.
          </p>
        </div>
      </section>

      <section className="experience-section experience-pillars" aria-labelledby="experience-pillars-title">
        <header>
          <p className="experience-kicker">What you get</p>
          <h2 id="experience-pillars-title">Evidence you can<br /><span>check yourself.</span></h2>
        </header>
        <article className="experience-pillar">
          <span className="experience-index">01</span>
          <h3>A clear verdict</h3>
          <p>One of three outcomes per scan. Never “safe”, because a static scan cannot prove that.</p>
        </article>
        <article className="experience-pillar">
          <span className="experience-index">02</span>
          <h3>The lines behind it</h3>
          <p>Every finding names its rule, file and line. You read the code; SPIDER points the way.</p>
        </article>
        <article className="experience-pillar">
          <span className="experience-index">03</span>
          <h3>Honest limits</h3>
          <p>Coverage is recorded with every scan: what was inspected, what was skipped, and why.</p>
        </article>
      </section>

      <section className="experience-section experience-verdicts" aria-labelledby="experience-verdicts-title">
        <div>
          <p className="experience-kicker">Three possible outcomes</p>
          <h2 id="experience-verdicts-title">Say what was found.<br /><span>Say what wasn’t.</span></h2>
        </div>
        <dl>
          <div><dt>Suspicious</dt><dd>A strong combination of signals. The evidence is shown for a person to judge.</dd></div>
          <div><dt>None detected in this scan</dt><dd>No strong signal in the code inspected. Not a safety claim.</dd></div>
          <div><dt>Unable to assess</dt><dd>Too much could not be inspected, so SPIDER says so instead of guessing.</dd></div>
        </dl>
      </section>

      <section className="experience-section experience-faq" aria-labelledby="experience-faq-title">
        <div>
          <p className="experience-kicker">Before you begin</p>
          <h2 id="experience-faq-title">Clear boundaries.<br /><span>Better decisions.</span></h2>
        </div>
        <div className="experience-faq__items">
          <details open>
            <summary>Does SPIDER run the package?</summary>
            <p>No. Package source is static input. The investigation does not import or execute submitted package code.</p>
          </details>
          <details>
            <summary>Does “no findings” mean safe?</summary>
            <p>No. Findings are bounded by the recorded coverage. Unsupported files, parse failures, and other limitations matter. Absence of findings is not proof of safety.</p>
          </details>
          <details>
            <summary>When does a request happen?</summary>
            <p>Only on explicit actions such as submitting, reading history, or opening a record.</p>
          </details>
          <details>
            <summary>Are model outputs required?</summary>
            <p>No. Static investigation works without models. Missing predictions and AI explanations remain unavailable; the interface does not invent them.</p>
          </details>
          <details>
            <summary>Which tool should I start with?</summary>
            <p>Use the Package Scanner for one package you are about to trust. Use the Environment Hunter to look through what is already installed on this machine.</p>
          </details>
          <details>
            <summary>How reliable is it?</summary>
            <p>The Results page lists the measured numbers and their limits, including false positives found on a manual check. They are signal rates, not an accuracy score.</p>
          </details>
          <details>
            <summary>What can it not see?</summary>
            <p>Compiled extensions, behaviour that only appears at runtime, and code disguised in ways the rules do not cover. The guide explains each case.</p>
          </details>
          <details>
            <summary>Where is my data kept?</summary>
            <p>Scans run against a local service. Saved records stay on that service and are reopened by ID from History.</p>
          </details>
        </div>
      </section>

      <section className="experience-closing">
        <div>
          <p className="experience-kicker">Start with a question. Follow the evidence.</p>
          <h2>Know what you’re<br /><span>looking at.</span></h2>
        </div>
        <div className="experience-closing__links">
          <RouteLink to="/hub">Choose a tool</RouteLink>
          <RouteLink to="/research">See measured results</RouteLink>
        </div>
      </section>
    </div>
  );
}
