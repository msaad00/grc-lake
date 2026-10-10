import {
  columnVisibilityFeature,
  createSortedRowModel,
  rowSortingFeature,
  sortFns,
  tableFeatures,
  type ColumnDef,
  type RowData,
} from "@tanstack/react-table";

/** Per-column hints for the shared `DataTable`. */
export interface TableColumnMeta {
  /**
   * Where the column lands in the phone card below `sm`: the card title, the
   * chip row, a labelled metadata line (default), or nowhere.
   */
  mobile?: "title" | "badge" | "meta" | "hidden";
  /**
   * The column renders the row's own open control (e.g. a Review button).
   * Where it is shown, `DataTable` adds no second control for the row.
   */
  rowAction?: boolean;
}

export const sortableTableFeatures = tableFeatures({
  columnVisibilityFeature,
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
  sortFns,
  columnMeta: {} as TableColumnMeta,
});

export type SortableTableFeatures = typeof sortableTableFeatures;

// ColumnDef is invariant in its value type, so a heterogeneous array of
// createColumnHelper accessors only unifies through the wildcard.
export type SortableColumnDefs<TData extends RowData> = Array<
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ColumnDef<SortableTableFeatures, TData, any>
>;
