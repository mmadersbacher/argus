import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Table } from "@/components/ui";

type Row = { id: string; name: string; risk: number };
const rows: Row[] = [
  { id: "a", name: "alpha", risk: 9 },
  { id: "b", name: "beta", risk: 3 },
];

const columns = [
  { key: "name", header: "Name" },
  { key: "risk", header: "Risk", numeric: true },
];

// (a) clicking a row calls onRowClick with that row's data
test("clicking a row calls onRowClick with row data", async () => {
  const onRowClick = vi.fn();
  render(
    <Table<Row>
      columns={columns}
      rows={rows}
      getRowId={(r) => r.id}
      onRowClick={onRowClick}
    />,
  );
  // When onRowClick is set, body <tr>s get role="button"
  const clickableRows = screen.getAllByRole("button").filter(
    (el) => el.tagName === "TR",
  );
  expect(clickableRows).toHaveLength(2);
  await userEvent.click(clickableRows[0]);
  expect(onRowClick).toHaveBeenCalledTimes(1);
  expect(onRowClick).toHaveBeenCalledWith(rows[0]);
});

// (b) focusing a row + pressing Enter calls onRowClick
test("pressing Enter on a focused row calls onRowClick", async () => {
  const onRowClick = vi.fn();
  render(
    <Table<Row>
      columns={columns}
      rows={rows}
      getRowId={(r) => r.id}
      onRowClick={onRowClick}
    />,
  );
  const clickableRows = screen.getAllByRole("button").filter(
    (el) => el.tagName === "TR",
  );
  expect(clickableRows).toHaveLength(2);
  clickableRows[1].focus();
  await userEvent.keyboard("{Enter}");
  expect(onRowClick).toHaveBeenCalledTimes(1);
  expect(onRowClick).toHaveBeenCalledWith(rows[1]);
});

// (c) clicking the selection checkbox does NOT call onRowClick
test("clicking selection checkbox does not trigger onRowClick", async () => {
  const onRowClick = vi.fn();
  const onSelectionChange = vi.fn();
  const selection = new Set<string>();
  render(
    <Table<Row>
      columns={columns}
      rows={rows}
      getRowId={(r) => r.id}
      onRowClick={onRowClick}
      selection={selection}
      onSelectionChange={onSelectionChange}
    />,
  );
  // Find the row checkboxes (aria-label "Select row a" / "Select row b")
  const checkbox = screen.getByRole("checkbox", { name: /Select row a/i });
  await userEvent.click(checkbox);
  // onSelectionChange fires but onRowClick must NOT
  expect(onSelectionChange).toHaveBeenCalled();
  expect(onRowClick).not.toHaveBeenCalled();
});
