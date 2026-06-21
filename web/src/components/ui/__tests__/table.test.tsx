import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Table } from "@/components/ui";

type Row = { id: string; name: string; risk: number };
const rows: Row[] = [{ id: "a", name: "alpha", risk: 9 }, { id: "b", name: "beta", risk: 3 }];

test("Table renders rows and toggles sort with aria-sort", async () => {
  const onSort = vi.fn();
  render(<Table<Row>
    columns={[{ key: "name", header: "Name", sortable: true }, { key: "risk", header: "Risk", numeric: true }]}
    rows={rows} getRowId={(r) => r.id}
    sort={{ key: "name", dir: "asc" }} onSortChange={onSort} />);
  expect(screen.getAllByRole("row")).toHaveLength(3); // header + 2
  expect(screen.getByRole("columnheader", { name: /Name/ })).toHaveAttribute("aria-sort", "ascending");
  await userEvent.click(screen.getByRole("button", { name: /Name/ }));
  expect(onSort).toHaveBeenCalledWith({ key: "name", dir: "desc" });
});

test("Table shows empty slot when no rows", () => {
  render(<Table<Row> columns={[{ key: "name", header: "Name" }]} rows={[]}
    getRowId={(r) => r.id} empty={<span>No data</span>} />);
  expect(screen.getByText("No data")).toBeInTheDocument();
});
