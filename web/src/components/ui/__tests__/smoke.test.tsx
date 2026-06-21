import { render, screen } from "@testing-library/react";
import { Button } from "@/components/ui";

test("ui barrel renders an existing primitive", () => {
  render(<Button>Save</Button>);
  expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
});
