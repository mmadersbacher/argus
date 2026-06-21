import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Checkbox } from "@/components/ui";

function Harness() {
  const [v, setV] = useState(false);
  return <Checkbox checked={v} onChange={setV} label="Select" />;
}
test("Checkbox toggles via label click and exposes role", async () => {
  render(<Harness />);
  const box = screen.getByRole("checkbox", { name: "Select" });
  expect(box).not.toBeChecked();
  await userEvent.click(screen.getByText("Select"));
  expect(box).toBeChecked();
});
