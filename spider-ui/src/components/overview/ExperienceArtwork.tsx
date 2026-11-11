import { useId, type CSSProperties } from 'react';

/** Original decorative geometry for the entry stage: a glowing isometric
 * artifact with an etched spider mark, orbit rings and a particle field.
 * Not a visualization of scan data, and not derived from any reference site's assets. */
export function ExperienceArtwork() {
  const id = useId().replace(/:/g, '');
  const particles = [
    [92, 208, 2.4, 0], [214, 122, 1.8, -3], [348, 214, 2.2, -6], [508, 96, 1.6, -1.5],
    [686, 148, 2.6, -4.5], [836, 236, 1.8, -2], [952, 330, 2.2, -5.5], [904, 470, 1.5, -3.5],
    [806, 640, 2.4, -1], [642, 762, 1.8, -6], [462, 796, 2.2, -2.5], [300, 742, 1.6, -4],
    [164, 626, 2.4, -1.8], [108, 468, 1.8, -5], [268, 336, 1.4, -2.8], [586, 264, 1.4, -4.2],
    [742, 330, 2.0, -0.8], [400, 420, 1.5, -5.2], [620, 560, 1.4, -3.2], [238, 548, 1.3, -1.2],
  ];
  const shards = [
    [96, 470, 118, 58, 26], [196, 604, 132, 66, 22], [736, 596, 148, 74, 30],
    [846, 452, 108, 54, 20], [664, 178, 120, 60, 24], [300, 190, 104, 52, 18],
  ];
  return <svg className="experience-artwork" viewBox="0 0 1040 880" fill="none" aria-hidden="true" focusable="false">
    <defs>
      <linearGradient id={`${id}-face`} x1="0" y1="0" x2="1" y2="1"><stop stopColor="#17594a" /><stop offset="0.55" stopColor="#0d332b" /><stop offset="1" stopColor="#061713" /></linearGradient>
      <linearGradient id={`${id}-side`} x1="0" y1="0" x2="0" y2="1"><stop stopColor="#11473a" /><stop offset="1" stopColor="#04100d" /></linearGradient>
      <linearGradient id={`${id}-top`} x1="0" y1="0" x2="1" y2="1"><stop stopColor="#83ebd1" /><stop offset="1" stopColor="#2aa78a" /></linearGradient>
      <radialGradient id={`${id}-halo`}><stop stopColor="#62e6c5" stopOpacity="0.34" /><stop offset="0.55" stopColor="#1f7a62" stopOpacity="0.12" /><stop offset="1" stopColor="#0b0d10" stopOpacity="0" /></radialGradient>
      <linearGradient id={`${id}-mirror`} x1="0" y1="0" x2="0" y2="1"><stop stopColor="#62e6c5" stopOpacity="0.28" /><stop offset="1" stopColor="#62e6c5" stopOpacity="0" /></linearGradient>
    </defs>
    <ellipse className="constellation-halo" cx="520" cy="430" rx="470" ry="350" fill={`url(#${id}-halo)`} />
    <g stroke="#1c2b26" strokeWidth="1">
      <path d="m84 452 436-230 436 230-436 238Z" />
      <path d="m40 592 480-254 480 254M148 724l372-198 372 198M268 822l464-246" />
      <path d="m180 300 580 310M348 214l564 304M88 522l508 270" />
    </g>
    <g className="constellation-orbits" stroke="#62e6c5" strokeOpacity="0.35">
      <ellipse cx="520" cy="430" rx="352" ry="196" strokeDasharray="2 12" />
      <ellipse className="constellation-orbit" cx="520" cy="430" rx="272" ry="150" strokeDasharray="140 1310" strokeWidth="1.5" />
      <ellipse cx="520" cy="430" rx="404" ry="228" strokeDasharray="1 16" strokeOpacity="0.2" />
    </g>
    {shards.map(([x, y, width, depth, height], index) => <g key={index} className={`constellation-tile constellation-tile--${index % 3}`} style={{ '--phase': `${index * -1.6}s` } as CSSProperties}>
      <path d={`M${x} ${y}l${width / 2} ${depth / 2} ${width / 2} ${-depth / 2}v${height}l${-width / 2} ${depth / 2} ${-width / 2} ${-depth / 2}Z`} fill={`url(#${id}-side)`} stroke="#1f4a3d" />
      <path d={`M${x} ${y}l${width / 2} ${-depth / 2} ${width / 2} ${depth / 2} ${-width / 2} ${depth / 2}Z`} fill={`url(#${id}-face)`} stroke="#2f8a70" strokeOpacity="0.7" />
      <path d={`M${x + width / 2 - 14} ${y - 3}l14 7 20-10`} stroke="#83ebd1" strokeOpacity="0.55" />
    </g>)}
    <ellipse cx="520" cy="618" rx="150" ry="30" fill="#62e6c5" opacity="0.14" />
    <ellipse className="stage-mirror" cx="520" cy="646" rx="132" ry="44" fill={`url(#${id}-mirror)`} />
    <g className="constellation-spider" strokeLinecap="round" strokeLinejoin="round">
      <path d="M520 128v64M520 128c-58 0-104 22-104 22M520 128c58 0 104 22 104 22" stroke="#2f8a70" strokeWidth="1.5" strokeDasharray="3 7" />
      {['M470 388 404 348 350 336 296 300', 'M468 420 392 408 322 444 250 444', 'M470 452 410 486 396 556 330 592',
        'M478 462 450 522 468 594 440 648', 'M570 388 636 348 690 336 744 300', 'M572 420 648 408 718 444 790 444',
        'M570 452 630 486 644 556 710 592', 'M562 462 590 522 572 594 600 648'].map((d, index) => <g key={d} className={`constellation-leg constellation-leg--${index % 2}`}>
        <path d={d} stroke="#06120e" strokeWidth="7" />
        <path d={d} stroke="#9ff0dc" strokeWidth="1.8" />
      </g>)}
      <path d="m520 372-30 30 9 48 21 26 21-26 9-48Z" fill={`url(#${id}-face)`} stroke="#a5f2df" strokeWidth="1.6" />
      <path d="m520 330-21 19 4 27h34l4-27Z" fill={`url(#${id}-top)`} stroke="#cdf5e9" strokeWidth="1.6" />
      <path d="m510 338 10-9 10 9M520 396v50" stroke="#c2f3e5" strokeOpacity="0.6" />
      <path d="m509 332-9-13m30 13 9-13" stroke="#62c9ae" strokeWidth="1.5" />
      <circle cx="512" cy="357" r="3.2" fill="#dcfaf0" /><circle cx="528" cy="357" r="3.2" fill="#dcfaf0" />
      <circle cx="512" cy="357" r="9" fill="#62e6c5" opacity="0.16" /><circle cx="528" cy="357" r="9" fill="#62e6c5" opacity="0.16" />
    </g>
    <g className="stage-cube" strokeLinejoin="round">
      <path d="m520 468-118-62 118-62 118 62Z" fill={`url(#${id}-top)`} stroke="#83ebd1" strokeOpacity="0.85" />
      <path d="m402 406v136l118 62V468Z" fill={`url(#${id}-side)`} stroke="#2f8a70" />
      <path d="m638 406v136l-118 62V468Z" fill={`url(#${id}-face)`} stroke="#2f8a70" />
      <path d="m402 406 118 62 118-62M402 542l118-74 118 74M520 468v136" stroke="#83ebd1" strokeOpacity="0.5" />
      <path d="m474 492 46-24 46 24-46 24Z" fill="#0d332b" stroke="#83ebd1" strokeOpacity="0.6" />
      <path d="m486 498 34 18m-34-2 34-18" stroke="#9ff0dc" strokeOpacity="0.5" />
    </g>
    <g fill="#c2f3e5">
      {particles.map(([cx, cy, r, delay], index) => <circle key={index} className="stage-particle" cx={cx} cy={cy} r={r} style={{ '--phase': `${delay}s` } as CSSProperties} />)}
    </g>
  </svg>;
}
