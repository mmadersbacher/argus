import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "@/components/ui";

test("Tooltip appears on focus with role tooltip", async () => {
  render(<Tooltip content="More info"><button>Q</button></Tooltip>);
  await userEvent.tab();
  expect(await screen.findByRole("tooltip", { name: "More info" })).toBeInTheDocument();
});
