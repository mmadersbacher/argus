import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Tabs, TabPanel } from "@/components/ui";

function Harness() {
  const [a, setA] = useState("one");
  return (<>
    <Tabs tabs={[{ id: "one", label: "One" }, { id: "two", label: "Two" }]} active={a} onChange={setA} />
    <TabPanel when="one" active={a}>First</TabPanel>
    <TabPanel when="two" active={a}>Second</TabPanel>
  </>);
}

test("Tabs switch panels and set aria-selected", async () => {
  render(<Harness />);
  expect(screen.getByText("First")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Two" }));
  expect(screen.getByRole("tab", { name: "Two" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("Second")).toBeInTheDocument();
});
