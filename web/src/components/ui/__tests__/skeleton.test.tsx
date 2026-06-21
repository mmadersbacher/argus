import { render, screen } from "@testing-library/react";
import { Skeleton, SkeletonTable } from "@/components/ui";

test("Skeleton is decorative and present", () => {
  render(<Skeleton variant="circle" width={24} height={24} />);
  const s = screen.getByTestId("skeleton");
  expect(s).toHaveAttribute("aria-hidden", "true");
});

test("SkeletonTable renders requested row count", () => {
  render(<SkeletonTable rows={3} cols={2} />);
  expect(screen.getAllByTestId("skeleton-row")).toHaveLength(3);
});
