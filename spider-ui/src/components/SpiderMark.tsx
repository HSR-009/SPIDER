import { useId } from "react";

interface SpiderMarkProps {
  compact?: boolean;
  className?: string;
}

/** Static, decorative geometry only: no assets, telemetry, animation, or pointer tracking. */
export function SpiderMark({ compact = false, className = "" }: SpiderMarkProps) {
  const id = useId();
  const bodyGradient = `${id}-body`;
  const webGradient = `${id}-web`;

  if (compact) {
    return (
      <svg className={className} viewBox="0 0 48 48" fill="none" aria-hidden="true" focusable="false">
        <path d="M22 19 13 10 7 12M21 23 10 18 4 23M21 27 10 30 7 39M23 30 17 39 19 45M26 19 35 10 41 12M27 23 38 18 44 23M27 27 38 30 41 39M25 30 31 39 29 45" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="m24 12-4 7 1 10 3 7 3-7 1-10-4-7Z" fill="currentColor" />
        <path d="m21 12 3-4 3 4" stroke="currentColor" strokeWidth="1.5" />
      </svg>
    );
  }

  return (
    <svg className={className} viewBox="0 0 600 540" fill="none" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={bodyGradient} x1="250" y1="185" x2="344" y2="355" gradientUnits="userSpaceOnUse">
          <stop stopColor="#ff7c91" />
          <stop offset="0.48" stopColor="#ff2d4d" />
          <stop offset="1" stopColor="#591428" />
        </linearGradient>
        <radialGradient id={webGradient} cx="0" cy="0" r="1" gradientTransform="translate(300 270) rotate(90) scale(265 290)" gradientUnits="userSpaceOnUse">
          <stop stopColor="#a778ff" stopOpacity="0.55" />
          <stop offset="0.64" stopColor="#a778ff" stopOpacity="0.18" />
          <stop offset="1" stopColor="#a778ff" stopOpacity="0" />
        </radialGradient>
      </defs>
      <g stroke={`url(#${webGradient})`} strokeWidth="1">
        <path d="M300 3v534M17 270h566M78 62l444 416M67 465 533 75M155 16l290 508M41 132l518 276M40 409l520-278M162 522 438 18" />
        <path d="M300 53Q335 109 402 85q-8 67 71 67-21 70 53 118-73 43-53 116-77-6-71 67-62-21-102 34-40-55-102-34 6-73-71-67 20-73-53-116 74-48 53-118 79 0 71-67 67 24 102-32Z" />
        <path d="M300 98q32 42 83 26-3 52 55 56-16 53 45 90-61 33-45 92-57-4-55 55-51-15-83 26-32-41-83-26 2-59-55-55 16-59-45-92 61-37 45-90 58-4 55-56 51 16 83-26Z" />
        <path d="M300 145q24 29 61 18 0 39 44 42-12 39 39 65-50 26-39 70-43-2-44 41-37-11-61 19-24-30-61-19-1-43-44-41 11-44-39-70 51-26 39-65 44-3 44-42 37 11 61-18Z" />
        <path d="M300 188q16 18 38 12 1 26 31 30-8 23 29 40-36 17-29 46-29-1-31 28-22-6-38 13-16-19-38-13-2-29-31-28 7-29-29-46 37-17 29-40 30-4 31-30 22 6 38-12Z" />
      </g>
      <g stroke="#a778ff" strokeOpacity="0.16">
        <circle cx="300" cy="270" r="231" strokeDasharray="2 12" />
        <ellipse cx="300" cy="270" rx="270" ry="189" transform="rotate(-24 300 270)" />
        <path d="M284 24h32M300 8v32M284 516h32M300 500v32M30 254v32M14 270h32M570 254v32M554 270h32" />
      </g>
      <g strokeLinecap="round" strokeLinejoin="round">
        <g stroke="#471e36" strokeWidth="10">
          <path d="M282 233 218 187 190 111 134 81M278 253 182 226 139 166 77 158M278 278 181 296 134 369 73 395M287 299 222 355 210 423 166 467M318 233 382 187 410 111 466 81M322 253 418 226 461 166 523 158M322 278 419 296 466 369 527 395M313 299 378 355 390 423 434 467" />
        </g>
        <g stroke={`url(#${bodyGradient})`} strokeWidth="3">
          <path d="M282 233 218 187 190 111 134 81M278 253 182 226 139 166 77 158M278 278 181 296 134 369 73 395M287 299 222 355 210 423 166 467M318 233 382 187 410 111 466 81M322 253 418 226 461 166 523 158M322 278 419 296 466 369 527 395M313 299 378 355 390 423 434 467" />
        </g>
        <path d="m291 214-14-19 7-14M309 214l14-19-7-14" stroke="#ff7c91" strokeWidth="3" />
      </g>
      <path d="M300 203c-20 0-28 17-24 38l10 28h28l10-28c4-21-4-38-24-38Z" fill={`url(#${bodyGradient})`} stroke="#ff8ea2" strokeOpacity="0.45" />
      <path d="M300 255c-20 0-34 16-33 40 1 27 19 52 33 62 14-10 32-35 33-62 1-24-13-40-33-40Z" fill={`url(#${bodyGradient})`} stroke="#ff8ea2" strokeOpacity="0.45" />
      <path d="m300 271-13 20 13 37 13-37-13-20Z" fill="#160d1d" fillOpacity="0.75" />
      <path d="m300 280-5 11 5 17 5-17-5-11Z" fill="#ff5873" />
      <path d="M294 221h3m6 0h3" stroke="#fff0f3" strokeWidth="2" strokeLinecap="round" />
      <g fill="#38e1ff">
        <circle cx="139" cy="166" r="3" />
        <circle cx="390" cy="423" r="3" />
        <circle cx="473" cy="152" r="2" />
      </g>
      <g stroke="#38e1ff" strokeOpacity="0.45">
        <path d="M124 166h-19M139 151v-19M405 423h19M390 438v19" />
      </g>
    </svg>
  );
}
