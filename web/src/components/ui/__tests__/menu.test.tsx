import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Menu } from "@/components/ui";

test("Menu opens and triggers item onSelect", async () => {
  const onSelect = vi.fn();
  render(<Menu trigger="Actions" items={[{ label: "Delete", tone: "danger", onSelect }]} />);
  await userEvent.click(screen.getByRole("button", { name: "Actions" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Delete" }));
  expect(onSelect).toHaveBeenCalledOnce();
});
