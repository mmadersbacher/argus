import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmDialog } from "@/components/ui";

test("ConfirmDialog confirms and is a modal dialog", async () => {
  const onConfirm = vi.fn(), onCancel = vi.fn();
  render(<ConfirmDialog open title="Revoke key?" body="This cannot be undone."
    confirmLabel="Revoke" tone="danger" onConfirm={onConfirm} onCancel={onCancel} />);
  expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
  await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
  expect(onConfirm).toHaveBeenCalledOnce();
});
