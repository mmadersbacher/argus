import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Pagination } from "@/components/ui";
import { describe, it, expect, vi } from "vitest";

describe("Pagination", () => {
  it("disables prev on first page and advances", async () => {
    const onChange = vi.fn();
    render(<Pagination page={1} pageCount={3} onPageChange={onChange} />);
    expect(screen.getByRole("button", { name: /previous/i })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(onChange).toHaveBeenCalledWith(2);
  });

  it("returns null when pageCount <= 1", () => {
    const onChange = vi.fn();
    const { container } = render(
      <Pagination page={1} pageCount={1} onPageChange={onChange} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("disables next on last page and goes back", async () => {
    const onChange = vi.fn();
    render(<Pagination page={3} pageCount={3} onPageChange={onChange} />);
    expect(screen.getByRole("button", { name: /next/i })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /previous/i }));
    expect(onChange).toHaveBeenCalledWith(2);
  });

  it("shows page indicator", () => {
    render(
      <Pagination page={2} pageCount={5} onPageChange={() => {}} />
    );
    expect(screen.getByText("Page 2 of 5")).toBeInTheDocument();
  });
});
