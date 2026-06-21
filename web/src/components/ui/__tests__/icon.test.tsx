import { render } from "@testing-library/react";
import { Icon } from "@/components/icon";

test.each(["copy", "eye", "eye-off", "info", "spinner"] as const)(
  "renders %s icon as svg",
  (name) => {
    const { container } = render(<Icon name={name} />);
    expect(container.querySelector("svg")).toBeInTheDocument();
  },
);
