"use client";
import { cx, focusRing } from "./internal";
import { Button, Checkbox } from "./controls";
import { Icon } from "@/components/icon";

export function Pagination({
  page,
  pageCount,
  onPageChange,
}: {
  page: number;
  pageCount: number;
  onPageChange: (p: number) => void;
}) {
  if (pageCount <= 1) return null;
  return (
    <div className="flex items-center justify-between gap-3 text-sm text-muted">
      <Button
        variant="secondary"
        size="sm"
        aria-label="Previous page"
        disabled={page <= 1}
        onClick={() => onPageChange(page - 1)}
      >
        Previous
      </Button>
      <span className="tabular-nums">
        Page {page} of {pageCount}
      </span>
      <Button
        variant="secondary"
        size="sm"
        aria-label="Next page"
        disabled={page >= pageCount}
        onClick={() => onPageChange(page + 1)}
      >
        Next
      </Button>
    </div>
  );
}

export type Column<Row> = {
  key: string;
  header: string;
  render?: (row: Row) => React.ReactNode;
  align?: "left" | "right";
  sortable?: boolean;
  numeric?: boolean;
  width?: string;
};

export type SortState = { key: string; dir: "asc" | "desc" };

export function Table<Row>({
  columns,
  rows,
  getRowId,
  sort,
  onSortChange,
  selection,
  onSelectionChange,
  onRowClick,
  density = "compact",
  empty,
  sticky,
}: {
  columns: Column<Row>[];
  rows: Row[];
  getRowId: (r: Row) => string;
  sort?: SortState;
  onSortChange?: (s: SortState) => void;
  selection?: Set<string>;
  onSelectionChange?: (s: Set<string>) => void;
  onRowClick?: (row: Row) => void;
  density?: "compact" | "comfortable";
  empty?: React.ReactNode;
  sticky?: boolean;
}) {
  const pad = density === "compact" ? "px-3 py-2" : "px-4 py-3";
  const selectable = Boolean(selection && onSelectionChange);
  const allSelected =
    selectable &&
    rows.length > 0 &&
    rows.every((r) => selection!.has(getRowId(r)));
  const toggleAll = () => {
    const next = new Set<string>();
    if (!allSelected) rows.forEach((r) => next.add(getRowId(r)));
    onSelectionChange!(next);
  };
  const toggleOne = (id: string) => {
    const next = new Set(selection);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onSelectionChange!(next);
  };
  const colCount = columns.length + (selectable ? 1 : 0);

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-surface-2 text-left text-muted">
          <tr>
            {selectable && (
              <th scope="col" className={cx(pad, "w-10", sticky && "sticky top-0 z-10 bg-surface-2")}>
                <Checkbox
                  checked={allSelected}
                  onChange={toggleAll}
                  ariaLabel="Select all rows"
                />
              </th>
            )}
            {columns.map((c) => {
              const active = sort?.key === c.key;
              return (
                <th
                  key={c.key}
                  scope="col"
                  style={{ width: c.width }}
                  aria-sort={
                    active
                      ? sort!.dir === "asc"
                        ? "ascending"
                        : "descending"
                      : undefined
                  }
                  className={cx(
                    pad,
                    "font-medium",
                    c.numeric || c.align === "right"
                      ? "text-right"
                      : "text-left",
                    sticky && "sticky top-0 z-10 bg-surface-2",
                  )}
                >
                  {c.sortable && onSortChange ? (
                    <button
                      type="button"
                      className={cx(
                        "inline-flex items-center gap-1 hover:text-fg",
                        focusRing,
                      )}
                      onClick={() =>
                        onSortChange({
                          key: c.key,
                          dir:
                            active && sort!.dir === "asc" ? "desc" : "asc",
                        })
                      }
                    >
                      {c.header}
                      {active ? <Icon name="chevron" size={13} /> : null}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={colCount}
                className={cx(pad, "text-center text-muted")}
              >
                {empty ?? "No data"}
              </td>
            </tr>
          ) : (
            rows.map((r) => {
              const id = getRowId(r);
              const clickable = Boolean(onRowClick);
              return (
                <tr
                  key={id}
                  className={cx(
                    "border-t border-line hover:bg-surface-2/60",
                    clickable && "cursor-pointer",
                  )}
                  {...(clickable
                    ? {
                        role: "button" as const,
                        tabIndex: 0,
                        onClick: () => onRowClick!(r),
                        onKeyDown: (e: React.KeyboardEvent<HTMLTableRowElement>) => {
                          if (e.key === "Enter") {
                            onRowClick!(r);
                          } else if (e.key === " ") {
                            e.preventDefault();
                            onRowClick!(r);
                          }
                        },
                      }
                    : {})}
                >
                  {selectable && (
                    <td className={pad} onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selection!.has(id)}
                        onChange={() => toggleOne(id)}
                        ariaLabel={`Select row ${id}`}
                      />
                    </td>
                  )}
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={cx(
                        pad,
                        c.numeric
                          ? "text-right tabular-nums"
                          : c.align === "right"
                            ? "text-right"
                            : "text-left",
                        "text-fg",
                      )}
                    >
                      {c.render
                        ? c.render(r)
                        : String(
                            (r as Record<string, unknown>)[c.key] ?? "",
                          )}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
