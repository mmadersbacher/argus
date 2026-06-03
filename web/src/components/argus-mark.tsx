// Argus mark — the "all-seeing eye" (iris + pupil) of the hundred-eyed watcher.
// Stroke uses currentColor so it inherits the surrounding text color (themeable).

export function ArgusMark({ size = 24 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      {/* eye almond (two mirrored curves) */}
      <path
        d="M3.5 12 Q12 5.2 20.5 12 Q12 18.8 3.5 12 Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      {/* iris */}
      <circle cx="12" cy="12" r="3.9" stroke="currentColor" strokeWidth="1.6" />
      {/* pupil */}
      <circle cx="12" cy="12" r="1.6" fill="currentColor" />
      {/* catchlight */}
      <circle cx="13.7" cy="10.5" r="0.6" fill="currentColor" opacity="0.75" />
    </svg>
  );
}
