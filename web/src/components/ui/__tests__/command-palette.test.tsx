import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CommandPalette } from "@/components/command-palette";
import { ThemeProvider } from "@/components/theme";

// Stub matchMedia for ThemeProvider
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

// Mock next/navigation
const mockPush = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush }),
}));

function renderPalette(open = true) {
  const onClose = vi.fn();
  render(
    <ThemeProvider>
      <CommandPalette open={open} onClose={onClose} />
    </ThemeProvider>,
  );
  return { onClose };
}

test("renders command palette open with search input and listbox", () => {
  renderPalette(true);
  expect(
    screen.getByPlaceholderText(/search commands/i),
  ).toBeInTheDocument();
  expect(screen.getByRole("listbox")).toBeInTheDocument();
});

test("does not render when closed", () => {
  renderPalette(false);
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
});

test('typing "vuln" shows only matching command(s)', async () => {
  const user = userEvent.setup();
  renderPalette(true);

  const input = screen.getByPlaceholderText(/search commands/i);
  await user.type(input, "vuln");

  // "Vulns" route should match, others (Overview, Assets, etc.) should not
  expect(screen.getByRole("option", { name: /vuln/i })).toBeInTheDocument();
  // A non-matching route like "Overview" should not appear
  expect(screen.queryByRole("option", { name: /overview/i })).not.toBeInTheDocument();
});

test("ArrowDown + Enter triggers the selected command action (navigate to /vulns)", async () => {
  const user = userEvent.setup();
  renderPalette(true);

  const input = screen.getByPlaceholderText(/search commands/i);
  await user.type(input, "vuln");

  // First option should now be the Vulns route — move selection down and confirm
  await user.keyboard("{ArrowDown}");
  await user.keyboard("{Enter}");

  expect(mockPush).toHaveBeenCalledWith("/vulns");
});
