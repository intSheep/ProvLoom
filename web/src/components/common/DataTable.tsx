import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { useId, useState } from "react";

interface DataTableProps<TData> {
  caption: string;
  data: TData[];
  columns: ColumnDef<TData, unknown>[];
  getRowId?: (row: TData, index: number) => string;
  selectedRowId?: string | null;
  onRowClick?: (row: TData) => void;
  isLoading?: boolean;
  emptyMessage?: string;
  maxHeightClass?: string;
  initialSorting?: SortingState;
}

export function DataTable<TData>({
  caption,
  data,
  columns,
  getRowId,
  selectedRowId,
  onRowClick,
  isLoading = false,
  emptyMessage = "当前查询范围下暂无数据。",
  maxHeightClass = "max-h-[540px]",
  initialSorting = [],
}: DataTableProps<TData>) {
  const captionId = useId();
  const [sorting, setSorting] = useState<SortingState>(initialSorting);
  const [sortAnnouncement, setSortAnnouncement] = useState("");

  const table = useReactTable({
    data,
    columns,
    getRowId,
    state: { sorting },
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      setSorting(next);
      if (next.length > 0) {
        const s = next[0];
        setSortAnnouncement(
          `Sorted by ${s.id}, ${s.desc ? "descending" : "ascending"}, ${data.length} rows`,
        );
      } else {
        setSortAnnouncement(`Sort cleared, ${data.length} rows`);
      }
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div className="relative">
      <div role="status" className="sr-only">
        {sortAnnouncement}
      </div>
      <div
        tabIndex={0}
        role="region"
        aria-labelledby={captionId}
        className={`pl-table-scroll ${maxHeightClass}`}
      >
        <table className="pl-table">
          <caption id={captionId} className="sr-only">
            {caption}
          </caption>
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  const canSort = header.column.getCanSort();
                  const sorted = header.column.getIsSorted();
                  const ariaSort =
                    sorted === "asc"
                      ? "ascending"
                      : sorted === "desc"
                        ? "descending"
                        : undefined;
                  return (
                    <th key={header.id} scope="col" aria-sort={ariaSort}>
                      {header.isPlaceholder ? null : canSort ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <span>
                            {flexRender(header.column.columnDef.header, header.getContext())}
                          </span>
                          <span className="sort-indicator" aria-hidden="true" />
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={columns.length} className="text-center py-8 text-[var(--pl-text-muted)]">
                  正在加载数据…
                </td>
              </tr>
            ) : table.getRowModel().rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="text-center py-8 text-[var(--pl-text-muted)]">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => {
                const isSelected = selectedRowId != null && row.id === selectedRowId;
                return (
                  <tr
                    key={row.id}
                    onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                    className={[
                      onRowClick ? "cursor-pointer" : "",
                      isSelected ? "bg-blue-500/15" : "",
                    ].join(" ")}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
