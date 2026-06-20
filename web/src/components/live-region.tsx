/** A visually-hidden polite live region for screen readers.
 *
 *  A polling view re-renders every few seconds, but `aria-live` only announces
 *  when the text content actually changes. Passing a *concise summary* string
 *  therefore announces a short delta ("12 assets, 3 high or critical") when the
 *  numbers move, instead of re-reading an entire data table on every refresh —
 *  which is why the live regions live here and not on the tables themselves.
 */
export function LiveRegion({ message }: { message: string }) {
  return (
    <p className="sr-only" role="status" aria-live="polite">
      {message}
    </p>
  );
}
