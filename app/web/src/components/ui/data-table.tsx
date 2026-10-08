"use client";

import type { KeyboardEvent, ReactNode } from "react";
import {
  flexRender,
  type Cell,
  type ReactTable,
  type RowData,
} from "@tanstack/react-table";
import { ArrowUpDown } from "lucide-react";
import type { SortableTableFeatures } from "@/lib/table-features";
import { SM_UP, useMediaQuery } from "@/lib/use-media-query";
import { cn } from "@/lib/utils";

type Density = "comfortable" | "compact";

const CELL: Record<Density, string> = {
  comfortable: "px-4 py-3",
  compact: "px-3 py-2.5",
};

interface Props<TData extends RowData> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  table: ReactTable<SortableTableFeatures, TData, any>;
  /** Accessible name of the scroll region (desktop) and card list (phone). */
  label: string;
  emptyLabel: ReactNode;
  onRowSelect?: (row: TData) => void;
  /** Accessible name for a selectable row or card. */
  rowLabel?: (row: TData) => string;
  density?: Density;
  /** Minimum table width before the region scrolls sideways. */
  minWidthClassName?: string;
  /** Extra classes for the desktop scroll region, e.g. a max height. */
  scrollClassName?: string;
}

function selectHandlers<TData>(
  row: TData,
  onRowSelect: ((row: TData) => void) | undefined,
  label: string | undefined,
) {
  if (!onRowSelect) return {};
  return {
    tabIndex: 0,
    "aria-label": label,
    onClick: () => onRowSelect(row),
    onKeyDown: (event: KeyboardEvent) => {
      if (event.target !== event.currentTarget) return;
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        onRowSelect(row);
      }
    },
  };
}

const SELECTABLE =
  "cursor-pointer hover:bg-info-bg focus-visible:bg-info-bg focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-brand";

/**
 * The console's one sortable data table. From `sm` up it is the dense table;
 * below `sm` each row becomes a card built from the same column definitions,
 * placed by `meta.mobile` (title, chip row, labelled metadata, or hidden), so
 * no column is lost in a sideways scroller on a phone.
 */
export function DataTable<TData extends RowData>({
  table,
  label,
  emptyLabel,
  onRowSelect,
  rowLabel,
  density = "comfortable",
  minWidthClassName = "min-w-[820px]",
  scrollClassName,
}: Props<TData>) {
  const wide = useMediaQuery(SM_UP);
  const rows = table.getRowModel().rows;

  if (!wide) {
    return (
      <ul
        aria-label={label}
        className="divide-y divide-line border-t border-line"
      >
        {rows.length === 0 ? (
          <li className="px-4 py-8 text-center text-sm text-muted">
            {emptyLabel}
          </li>
        ) : null}
        {rows.map((row) => {
          const cells = row.getVisibleCells();
          const place = (cell: Cell<SortableTableFeatures, TData, unknown>) =>
            cell.column.columnDef.meta?.mobile ?? "meta";
          const render = (cell: Cell<SortableTableFeatures, TData, unknown>) =>
            flexRender(cell.column.columnDef.cell, cell.getContext());
          const titles = cells.filter((cell) => place(cell) === "title");
          const badges = cells.filter((cell) => place(cell) === "badge");
          const meta = cells.filter((cell) => place(cell) === "meta");
          return (
            <li
              key={row.id}
              data-testid="data-card"
              {...selectHandlers(
                row.original,
                onRowSelect,
                rowLabel?.(row.original),
              )}
              role={onRowSelect ? "button" : undefined}
              className={cn(
                "grid min-w-0 gap-2 px-4 py-3",
                onRowSelect && SELECTABLE,
              )}
            >
              {titles.map((cell) => (
                <div key={cell.id} className="min-w-0 [overflow-wrap:anywhere]">
                  {render(cell)}
                </div>
              ))}
              {badges.length > 0 ? (
                <div className="flex min-w-0 flex-wrap items-start gap-2">
                  {badges.map((cell) => (
                    <div key={cell.id} className="min-w-0">
                      {render(cell)}
                    </div>
                  ))}
                </div>
              ) : null}
              {meta.length > 0 ? (
                <dl className="grid min-w-0 grid-cols-[minmax(0,7rem)_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-xs">
                  {meta.map((cell) => {
                    const header = cell.column.columnDef.header;
                    return (
                      <div key={cell.id} className="contents">
                        <dt className="pt-0.5 font-medium text-muted">
                          {typeof header === "string" ? header : cell.column.id}
                        </dt>
                        <dd className="min-w-0 [overflow-wrap:anywhere] [&_*]:max-w-full">
                          {render(cell)}
                        </dd>
                      </div>
                    );
                  })}
                </dl>
              ) : null}
            </li>
          );
        })}
      </ul>
    );
  }

  const cellPadding = CELL[density];
  return (
    <div
      className={cn("max-w-full overflow-x-auto", scrollClassName)}
      role="region"
      aria-label={label}
      // Keyboard users reach the columns past the fold through this region.
      tabIndex={0}
    >
      <table className={cn("w-full text-sm", minWidthClassName)}>
        <thead>
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id} className="border-y border-line bg-surfaceMuted">
              {hg.headers.map((h) => {
                const sortable = h.column.getCanSort();
                const sorted = h.column.getIsSorted();
                const toggle = h.column.getToggleSortingHandler();
                return (
                  <th
                    key={h.id}
                    scope="col"
                    aria-sort={
                      sorted === "asc"
                        ? "ascending"
                        : sorted === "desc"
                          ? "descending"
                          : undefined
                    }
                    onClick={sortable ? toggle : undefined}
                    className={cn(
                      "whitespace-nowrap text-left text-[11px] font-semibold uppercase tracking-wide text-muted",
                      cellPadding,
                      sortable && "cursor-pointer",
                    )}
                  >
                    {sortable ? (
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          toggle?.(event);
                        }}
                        className="inline-flex items-center gap-1 text-left uppercase"
                      >
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        <ArrowUpDown
                          aria-hidden="true"
                          className="h-3 w-3 opacity-40"
                        />
                      </button>
                    ) : (
                      flexRender(h.column.columnDef.header, h.getContext())
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.id}
              {...selectHandlers(
                r.original,
                onRowSelect,
                rowLabel?.(r.original),
              )}
              className={cn(
                "border-b border-line last:border-0",
                onRowSelect ? SELECTABLE : "hover:bg-info-bg",
              )}
            >
              {r.getVisibleCells().map((c) => (
                <td key={c.id} className={cn(cellPadding, "align-top")}>
                  {flexRender(c.column.columnDef.cell, c.getContext())}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td
                className="px-4 py-8 text-center text-sm text-muted"
                colSpan={table.getVisibleLeafColumns().length}
              >
                {emptyLabel}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
