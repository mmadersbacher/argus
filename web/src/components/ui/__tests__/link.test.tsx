import { render, screen } from "@testing-library/react";
import { Link, ButtonLink } from "@/components/ui";

test("external Link is safe and labelled", () => {
  render(<Link href="https://x.test" external>CVE-2024-1</Link>);
  const a = screen.getByRole("link", { name: /CVE-2024-1/ });
  expect(a).toHaveAttribute("target", "_blank");
  expect(a).toHaveAttribute("rel", expect.stringContaining("noopener"));
});

test("ButtonLink renders an anchor styled as a button", () => {
  render(<ButtonLink href="/assets" variant="secondary">Open</ButtonLink>);
  expect(screen.getByRole("link", { name: "Open" })).toHaveAttribute("href", "/assets");
});
