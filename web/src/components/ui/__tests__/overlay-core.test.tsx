import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Portal } from "@/components/ui/overlay-core";

test("Portal renders children into document.body", () => {
  render(<Portal><button>inside</button></Portal>);
  const btn = screen.getByRole("button", { name: "inside" });
  expect(btn.closest("body")).toBe(document.body);
});
