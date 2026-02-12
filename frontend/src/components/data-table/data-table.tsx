import {
  type ColumnDef,
  type SortingState,
  type PaginationState,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import { cn } from '@/lib/utils.ts';
import { Button } from '@/components/ui/button.tsx';
import { TableSkeleton } from '@/components/loading-skeleton.tsx';
import { EmptyState } from '@/components/empty-state.tsx';

interface DataTableProps<TData> {
  columns: ColumnDef<TData, unknown>[];
  data: TData[];
  totalRows?: number;
  pagination?: PaginationState;
  onPaginationChange?: (pagination: PaginationState) => void;
  sorting?: SortingState;
  onSortingChange?: (sorting: SortingState) => void;
  isLoading?: boolean;
  emptyMessage?: string;
  emptyDescription?: string;
  onRowClick?: (row: TData) => void;
}

export function DataTable<TData>({
  columns,
  data,
  totalRows,
  pagination,
  onPaginationChange,
  sorting,
  onSortingChange,
  isLoading,
  emptyMessage = 'No data found',
  emptyDescription,
  onRowClick,
}: DataTableProps<TData>) {
  const pageCount = totalRows && pagination ? Math.ceil(totalRows / pagination.pageSize) : -1;

  const table = useReactTable({
    data,
    columns,
    pageCount,
    state: {
      sorting: sorting ?? [],
      pagination: pagination ?? { pageIndex: 0, pageSize: 50 },
    },
    onSortingChange: onSortingChange
      ? (updater) => {
          const next = typeof updater === 'function' ? updater(sorting ?? []) : updater;
          onSortingChange(next);
        }
      : undefined,
    onPaginationChange: onPaginationChange
      ? (updater) => {
          const next = typeof updater === 'function'
            ? updater(pagination ?? { pageIndex: 0, pageSize: 50 })
            : updater;
          onPaginationChange(next);
        }
      : undefined,
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    manualSorting: true,
  });

  if (isLoading) return <TableSkeleton rows={pagination?.pageSize ?? 5} />;

  if (data.length === 0) {
    return <EmptyState title={emptyMessage} description={emptyDescription} />;
  }

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-[var(--muted)]">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className={cn(
                      'h-10 px-4 text-left font-medium text-[var(--muted-foreground)]',
                      header.column.getCanSort() && 'cursor-pointer select-none',
                    )}
                    onClick={header.column.getToggleSortingHandler()}
                    onKeyDown={header.column.getCanSort() ? (e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        header.column.getToggleSortingHandler()?.(e);
                      }
                    } : undefined}
                    tabIndex={header.column.getCanSort() ? 0 : undefined}
                    aria-sort={
                      header.column.getIsSorted() === 'asc' ? 'ascending' :
                      header.column.getIsSorted() === 'desc' ? 'descending' :
                      header.column.getCanSort() ? 'none' : undefined
                    }
                  >
                    <div className="flex items-center gap-1">
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getCanSort() && (
                        header.column.getIsSorted() === 'asc' ? <ArrowUp className="h-3.5 w-3.5" aria-hidden="true" /> :
                        header.column.getIsSorted() === 'desc' ? <ArrowDown className="h-3.5 w-3.5" aria-hidden="true" /> :
                        <ArrowUpDown className="h-3.5 w-3.5 opacity-40" aria-hidden="true" />
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                className={cn(
                  'border-t transition-colors hover:bg-[var(--muted)]',
                  onRowClick && 'cursor-pointer',
                )}
                onClick={() => onRowClick?.(row.original)}
                onKeyDown={onRowClick ? (e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onRowClick(row.original);
                  }
                } : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                role={onRowClick ? 'link' : undefined}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-3">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pagination && onPaginationChange && totalRows !== undefined && (
        <nav className="flex items-center justify-between" aria-label="Table pagination">
          <p className="text-sm text-[var(--muted-foreground)]">
            {totalRows.toLocaleString()} total results
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Previous
            </Button>
            <span className="text-sm">
              Page {pagination.pageIndex + 1} of {pageCount > 0 ? pageCount : 1}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </nav>
      )}
    </div>
  );
}
