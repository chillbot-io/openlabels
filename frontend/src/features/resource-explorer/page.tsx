import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { FileText, ShieldAlert, Search, ChevronRight, FolderOpen } from 'lucide-react';
import { browseApi } from '@/api/endpoints/browse.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { FolderTreePanel } from '@/components/folder-tree.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { EmptyState } from '@/components/empty-state.tsx';
import { EntityTag } from '@/components/entity-tag.tsx';
import { useDebounce } from '@/hooks/use-debounce.ts';
import { formatDateTime } from '@/lib/date.ts';
import { RISK_TIERS, type RiskTier } from '@/lib/constants.ts';
import type { BrowseFolder, BrowseFile } from '@/api/types.ts';

function formatSize(bytes: number | null): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/** Split a path into breadcrumb segments. */
function pathSegments(dirPath: string): string[] {
  // Handle both Windows and Unix paths
  const sep = dirPath.includes('\\') ? '\\' : '/';
  return dirPath.split(sep).filter(Boolean);
}

function Breadcrumbs({ path }: { path: string }) {
  const segments = pathSegments(path);
  return (
    <nav className="flex items-center gap-1 text-sm text-[var(--muted-foreground)]" aria-label="Breadcrumb">
      <FolderOpen className="h-3.5 w-3.5 shrink-0" />
      {segments.map((segment, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <ChevronRight className="h-3 w-3 shrink-0" />}
          <span className={i === segments.length - 1 ? 'font-medium text-[var(--foreground)]' : ''}>
            {segment}
          </span>
        </span>
      ))}
    </nav>
  );
}

function RiskFilterPills({ value, onChange }: { value: string | null; onChange: (v: string | null) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      <button
        className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
          value === null
            ? 'bg-[var(--foreground)] text-[var(--background)]'
            : 'bg-[var(--muted)] text-[var(--muted-foreground)] hover:bg-[var(--accent)]'
        }`}
        onClick={() => onChange(null)}
      >
        All
      </button>
      {RISK_TIERS.map((tier) => (
        <button
          key={tier}
          className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
            value === tier
              ? 'bg-[var(--foreground)] text-[var(--background)]'
              : 'bg-[var(--muted)] text-[var(--muted-foreground)] hover:bg-[var(--accent)]'
          }`}
          onClick={() => onChange(tier)}
        >
          {tier}
        </button>
      ))}
    </div>
  );
}

function FileRow({ file, onClick }: { file: BrowseFile; onClick: () => void }) {
  return (
    <button
      className="flex w-full items-center gap-3 border-b px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-[var(--muted)]/50"
      onClick={onClick}
    >
      <FileText className="h-4 w-4 shrink-0 text-[var(--muted-foreground)]" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{file.file_name}</p>
        <div className="flex flex-wrap gap-1 pt-0.5">
          {Object.entries(file.entity_counts).slice(0, 3).map(([type, count]) => (
            <EntityTag key={type} type={type} count={count} />
          ))}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {file.current_label_name && (
          <Badge variant="outline" className="text-xs">{file.current_label_name}</Badge>
        )}
        {file.exposure_level && file.exposure_level !== 'PRIVATE' && (
          <Badge variant="outline" className="text-xs">{file.exposure_level}</Badge>
        )}
        <RiskBadge tier={file.risk_tier as RiskTier} />
        <span className="w-16 text-right text-xs text-[var(--muted-foreground)]">{formatSize(file.file_size)}</span>
        <ChevronRight className="h-4 w-4 text-[var(--muted-foreground)]" />
      </div>
    </button>
  );
}

function FilesPanel({ targetId, folder }: { targetId: string; folder: BrowseFolder }) {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<string | null>(null);
  const debouncedSearch = useDebounce(search, 300);

  // Reset filters when folder changes
  useEffect(() => {
    setSearch('');
    setRiskFilter(null);
  }, [folder.id]);

  const files = useQuery({
    queryKey: ['browse', targetId, 'files', folder.dir_path, riskFilter, debouncedSearch],
    queryFn: () => browseApi.files(targetId, {
      folder_path: folder.dir_path,
      risk_tier: riskFilter ?? undefined,
      search: debouncedSearch || undefined,
    }),
    enabled: !!targetId && !!folder.dir_path,
  });

  const handleFileClick = (file: BrowseFile) => {
    if (file.latest_result_id) {
      navigate(`/results/${file.latest_result_id}`);
    }
  };

  const fileList = files.data?.files ?? [];
  const total = files.data?.total ?? 0;

  return (
    <div className="flex-1 overflow-y-auto p-6">
      {/* Breadcrumbs */}
      <div className="mb-4">
        <Breadcrumbs path={folder.dir_path} />
      </div>

      {/* Folder info card */}
      <Card className="mb-4">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              {folder.dir_name}
              {folder.highest_risk_tier && <RiskBadge tier={folder.highest_risk_tier as RiskTier} />}
            </CardTitle>
          </div>
          <div className="flex flex-wrap gap-4 pt-1 text-xs text-[var(--muted-foreground)]">
            <span>{folder.child_dir_count ?? 0} folders</span>
            <span>{folder.child_file_count ?? 0} files</span>
            <span>{folder.total_entities_found ?? 0} entities found</span>
            {folder.last_scanned_at && <span>Last scanned {formatDateTime(folder.last_scanned_at)}</span>}
          </div>
          {(folder.world_accessible || folder.authenticated_users) && (
            <div className="flex items-center gap-2 pt-1">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              {folder.world_accessible && <span className="text-xs font-medium text-red-600">World Accessible</span>}
              {folder.authenticated_users && <span className="text-xs font-medium text-yellow-600">Authenticated Users</span>}
            </div>
          )}
        </CardHeader>
      </Card>

      {/* Search + filter bar */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-[var(--muted-foreground)]" />
          <Input
            placeholder="Search files..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            aria-label="Search files in folder"
          />
        </div>
        <RiskFilterPills value={riskFilter} onChange={setRiskFilter} />
      </div>

      {/* Files list */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">
            Sensitive Files
            {total > 0 && <span className="ml-2 text-sm font-normal text-[var(--muted-foreground)]">({total})</span>}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {files.isLoading ? (
            <div className="space-y-1 p-4">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}
            </div>
          ) : fileList.length === 0 ? (
            <div className="p-8 text-center text-sm text-[var(--muted-foreground)]">
              {search || riskFilter ? 'No files match your filters' : 'No sensitive files found in this folder'}
            </div>
          ) : (
            <div role="list" aria-label="Files">
              {fileList.map((file) => (
                <FileRow key={file.id} file={file} onClick={() => handleFileClick(file)} />
              ))}
              {total > fileList.length && (
                <div className="p-3 text-center text-xs text-[var(--muted-foreground)]">
                  Showing {fileList.length} of {total} files
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export function Component() {
  const targets = useTargets();
  const [targetId, setTargetId] = useState('');
  const [selectedFolder, setSelectedFolder] = useState<BrowseFolder | null>(null);

  // Auto-select when there's only one target
  useEffect(() => {
    const items = targets.data?.items ?? [];
    if (items.length === 1 && !targetId) {
      setTargetId(items[0].id);
    }
  }, [targets.data, targetId]);

  return (
    <div className="flex h-[calc(100vh-3.5rem)] flex-col overflow-hidden">
      {/* Page header */}
      <div className="border-b px-6 py-4">
        <h1 className="text-2xl font-bold">Resource Explorer</h1>
        <p className="text-sm text-[var(--muted-foreground)]">
          Browse your data sources and drill into folders to find sensitive files
        </p>
      </div>

      {/* Two-panel layout */}
      <div className="flex flex-1 overflow-hidden">
        <FolderTreePanel
          targetId={targetId}
          onTargetChange={(id) => { setTargetId(id); setSelectedFolder(null); }}
          onSelect={setSelectedFolder}
          selectedId={selectedFolder?.id ?? null}
        />

        <div className="flex flex-1 flex-col overflow-hidden">
          {selectedFolder ? (
            <FilesPanel targetId={targetId} folder={selectedFolder} />
          ) : (
            <EmptyState
              icon={FileText}
              title={targetId ? 'Select a folder' : 'Select a data source'}
              description={
                targetId
                  ? 'Browse the folder tree on the left and select a folder to see its sensitive files'
                  : 'Choose a scan target from the dropdown to start browsing'
              }
            />
          )}
        </div>
      </div>
    </div>
  );
}
