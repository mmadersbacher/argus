// Candidate Argus logo marks (currentColor, 24x24 viewBox). Compared at /brand.
// The chosen one gets promoted into argus-mark.tsx + app/icon.svg.

type MarkProps = { size?: number };

/** Eye v2 — almond with a concentric iris/lens (refined "watcher / sensor"). */
export function MarkEye({ size = 24 }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M3.5 12 Q12 5.2 20.5 12 Q12 18.8 3.5 12 Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12" cy="12" r="2.1" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12" cy="12" r="0.9" fill="currentColor" />
    </svg>
  );
}

/** Monogram A — geometric "A" with an apex node. */
export function MarkA({ size = 24 }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3.6 L4.5 20.4 M12 3.6 L19.5 20.4 M7.9 14.4 H16.1"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="3.8" r="1.5" fill="currentColor" />
    </svg>
  );
}

/** Radar sweep — scan rings + a detected asset (discovery motif). */
export function MarkRadar({ size = 24 }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" opacity="0.9" />
      <circle cx="12" cy="12" r="4.6" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 12 L19.4 6.9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="12" cy="12" r="1.3" fill="currentColor" />
      <circle cx="18.7" cy="6.4" r="1.5" fill="currentColor" />
    </svg>
  );
}

/** Asset graph — a central node linked to satellites (CAASM relationships). */
export function MarkNodes({ size = 24 }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 12 L5.5 6 M12 12 L19 7 M12 12 L12.5 19.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <circle cx="12" cy="12" r="2.5" fill="currentColor" />
      <circle cx="5.5" cy="6" r="1.9" fill="currentColor" />
      <circle cx="19" cy="7" r="1.9" fill="currentColor" />
      <circle cx="12.5" cy="19.5" r="1.9" fill="currentColor" />
    </svg>
  );
}
