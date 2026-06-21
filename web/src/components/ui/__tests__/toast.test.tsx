import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider, useToast } from "@/components/ui";

function Trigger() {
  const { toast } = useToast();
  return <button onClick={() => toast({ title: "Saved", tone: "ok" })}>go</button>;
}
test("toast() shows a message in a live region", async () => {
  render(<ToastProvider><Trigger /></ToastProvider>);
  await userEvent.click(screen.getByRole("button", { name: "go" }));
  expect(await screen.findByText("Saved")).toBeInTheDocument();
});
