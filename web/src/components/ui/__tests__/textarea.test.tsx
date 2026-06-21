import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Textarea } from "@/components/ui";

test("Textarea accepts input and forwards props", async () => {
  render(<Textarea aria-label="notes" rows={4} />);
  const el = screen.getByLabelText("notes");
  await userEvent.type(el, "hello");
  expect(el).toHaveValue("hello");
});
