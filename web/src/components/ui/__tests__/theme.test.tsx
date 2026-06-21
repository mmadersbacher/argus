import { render, act } from "@testing-library/react";
import { ThemeProvider, useTheme } from "@/components/theme";

// jsdom does not implement matchMedia — provide a minimal stub
beforeEach(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  });
});

function Consumer({ onMount }: { onMount: (ctx: ReturnType<typeof useTheme>) => void }) {
  const ctx = useTheme();
  onMount(ctx);
  return null;
}

test("setTheme('dark') adds .dark to documentElement and persists to localStorage", () => {
  let ctx!: ReturnType<typeof useTheme>;
  render(
    <ThemeProvider>
      <Consumer onMount={(c) => { ctx = c; }} />
    </ThemeProvider>,
  );

  act(() => {
    ctx.setTheme("dark");
  });

  expect(document.documentElement.classList.contains("dark")).toBe(true);
  expect(localStorage.getItem("argus-theme")).toBe("dark");
});

test("setTheme('light') removes .dark from documentElement and persists to localStorage", () => {
  // Start with dark so we can verify removal
  document.documentElement.classList.add("dark");

  let ctx!: ReturnType<typeof useTheme>;
  render(
    <ThemeProvider>
      <Consumer onMount={(c) => { ctx = c; }} />
    </ThemeProvider>,
  );

  act(() => {
    ctx.setTheme("light");
  });

  expect(document.documentElement.classList.contains("dark")).toBe(false);
  expect(localStorage.getItem("argus-theme")).toBe("light");
});
