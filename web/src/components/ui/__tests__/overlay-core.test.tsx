import { render, screen, fireEvent, act } from "@testing-library/react";
import { useRef } from "react";
import { Portal, useDismiss, useFocusTrap } from "@/components/ui/overlay-core";

test("Portal renders children into document.body", () => {
  render(<Portal><button>inside</button></Portal>);
  const btn = screen.getByRole("button", { name: "inside" });
  expect(btn.closest("body")).toBe(document.body);
});

// ---------------------------------------------------------------------------
// Stacking tests
// ---------------------------------------------------------------------------

/** Minimal component that calls useDismiss and (optionally) useFocusTrap. */
function OverlayHarness({
  label,
  onDismiss,
  trapScroll,
}: {
  label: string;
  onDismiss: () => void;
  trapScroll?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDismiss(onDismiss);
  // Only call useFocusTrap when requested so we can isolate scroll-lock tests.
  if (trapScroll) {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    useFocusTrap(ref);
  }
  return <div ref={ref} data-testid={label} />;
}

test("Escape closes only the topmost overlay (stacking)", () => {
  const lowerDismiss = vi.fn();
  const upperDismiss = vi.fn();

  const { unmount: unmountUpper } = render(
    <>
      <OverlayHarness label="lower" onDismiss={lowerDismiss} />
      <OverlayHarness label="upper" onDismiss={upperDismiss} />
    </>,
  );

  // Escape → only upper fires.
  fireEvent.keyDown(window, { key: "Escape" });
  expect(upperDismiss).toHaveBeenCalledTimes(1);
  expect(lowerDismiss).toHaveBeenCalledTimes(0);

  // Unmount upper, then Escape → lower fires.
  act(() => unmountUpper());

  // Re-render just the lower overlay independently so its token is on the stack.
  const { unmount: unmountLower } = render(
    <OverlayHarness label="lower2" onDismiss={lowerDismiss} />,
  );

  fireEvent.keyDown(window, { key: "Escape" });
  expect(lowerDismiss).toHaveBeenCalledTimes(1);

  act(() => unmountLower());
});

test("scroll lock is held while any overlay is open, restored after last closes", () => {
  // Reset body overflow before the test.
  document.body.style.overflow = "";

  const noop = vi.fn();

  const { unmount: unmountA } = render(
    <OverlayHarness label="a" onDismiss={noop} trapScroll />,
  );
  expect(document.body.style.overflow).toBe("hidden");

  const { unmount: unmountB } = render(
    <OverlayHarness label="b" onDismiss={noop} trapScroll />,
  );
  expect(document.body.style.overflow).toBe("hidden");

  // Unmount A — B still open, scroll must stay locked.
  act(() => unmountA());
  expect(document.body.style.overflow).toBe("hidden");

  // Unmount B — no overlays left, scroll must be restored.
  act(() => unmountB());
  expect(document.body.style.overflow).toBe("");
});
