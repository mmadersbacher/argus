export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
export const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40";
