// Argus mark — the "all-seeing eye" of the hundred-eyed watcher: an almond eye
// with a concentric iris/lens. Stroke uses currentColor so it inherits the
// surrounding text color (themeable).

export function ArgusMark({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      {/* eye almond (two mirrored curves) */}
      <path
        d="M3.2 12 Q12 5 20.8 12 Q12 19 3.2 12 Z"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      {/* iris + lens ring */}
      <circle cx="12" cy="12" r="4.1" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12" cy="12" r="2.1" stroke="currentColor" strokeWidth="1.4" />
      {/* pupil */}
      <circle cx="12" cy="12" r="0.95" fill="currentColor" />
    </svg>
  );
}
