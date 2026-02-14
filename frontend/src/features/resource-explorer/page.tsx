import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileText, ShieldAlert } from 'lucide-react';
import { browseApi } from '@/api/endpoints/browse.ts';
import { FolderTreePanel } from '@/components/folder-tree.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { EmptyState } from '@/components/empty-state.tsx';
import { formatDateTime } from '@/lib/date.ts';
import type { BrowseFolder, BrowseFile } from '@/api/types.ts';
import type { RiskTier } from '@/lib/constants.ts';

function formatSize(bytes: number | null): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function FileRow({ file }: { file: BrowseFile }) {
  return (
    <div className="flex items-center gap-3 border-b px-4 py-3 last:border-b-0">
      <FileText className="h-4 w-4 shrink-0 text-[var(--muted-foreground)]" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{file.file_name}</p>
        <p className="truncate text-xs text-[var(--muted-foreground)]">{file.file_path}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {file.total_entities > 0 && (
          <span className="text-xs text-[var(--muted-foreground)]">{file.total_entities} entities</span>
        )}
        {file.current_label_name && (
          <Badge variant="outline" className="text-xs">{file.current_label_name}</Badge>
        )}
        {file.exposure_level && (
          <Badge variant="outline" className="text-xs">{file.exposure_level}</Badge>
        )}
        <RiskBadge tier={file.risk_tier as RiskTier} />
        <span className="w-16 text-right text-xs text-[var(--muted-foreground)]">{formatSize(file.file_size)}</span>
      </div>
    </div>
  );
}

function FilesPanel({ targetId, folder }: { targetId: string; folder: BrowseFolder }) {
  const files = useQuery({
    queryKey: ['browse', targetId, 'files', folder.dir_path],
    queryFn: () => browseApi.files(targetId, { folder_path: folder.dir_path }),
    enabled: !!targetId && !!folder.dir_path,
  });

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            {folder.dir_name}
            {folder.highest_risk_tier && <RiskBadge tier={folder.highest_risk_tier as RiskTier} />}
          </CardTitle>
          <p className="text-sm text-[var(--muted-foreground)]">{folder.dir_path}</p>
          <div className="flex flex-wrap gap-4 pt-2 text-xs text-[var(--muted-foreground)]">
            <span>{folder.child_dir_count ?? 0} folders</span>
            <span>{folder.child_file_count ?? 0} files</span>
            <span>{folder.total_entities_found ?? 0} entities</span>
            {folder.last_scanned_at && <span>Scanned {formatDateTime(folder.last_scanned_at)}</span>}
          </div>
          {(folder.world_accessible || folder.authenticated_users) && (
            <div className="flex items-center gap-2 pt-1">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              {folder.world_accessible && <span className="text-xs font-medium text-red-600">World Accessible</span>}
              {folder.authenticated_users && <span className="text-xs font-medium text-yellow-600">Authenticated Users</span>}
            </div>
          )}
        </CardHeader>
        <CardContent className="p-0">
          {files.isLoading ? (
            <div className="space-y-1 p-4">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : (files.data?.files ?? []).length === 0 ? (
            <div className="p-8 text-center text-sm text-[var(--muted-foreground)]">No sensitive files found in this folder</div>
          ) : (
            <div role="list" aria-label="Files">
              {(files.data?.files ?? []).map((file) => (
                <FileRow key={file.id} file={file} />
              ))}
              {files.data && files.data.total > files.data.files.length && (
                <div className="p-3 text-center text-xs text-[var(--muted-foreground)]">
                  Showing {files.data.files.length} of {files.data.total} files
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
  const [targetId, setTargetId] = useState('');
  const [selectedFolder, setSelectedFolder] = useState<BrowseFolder | null>(null);

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
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
          <EmptyState icon={FileText} title="Select a folder" description="Browse the folder tree and select a folder to see its sensitive files" />
        )}
      </div>
    </div>
  );
}
