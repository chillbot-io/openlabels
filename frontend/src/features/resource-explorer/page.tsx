import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FolderOpen, ChevronRight, ChevronDown, AlertCircle } from 'lucide-react';
import { browseApi } from '@/api/endpoints/browse.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { cn } from '@/lib/utils.ts';
import type { BrowseFolder } from '@/api/types.ts';
import type { RiskTier } from '@/lib/constants.ts';

function FolderTreeItem({ folder, targetId, onSelect, selectedId }: {
  folder: BrowseFolder;
  targetId: string;
  onSelect: (folder: BrowseFolder) => void;
  selectedId: string | null;
}) {
  const [expanded, setExpanded] = useState(false);

  const children = useQuery({
    queryKey: ['browse', targetId, folder.id],
    queryFn: () => browseApi.list(targetId, folder.id),
    enabled: expanded,
  });

  const childFolders = children.data?.folders ?? [];
  const isSelected = selectedId === folder.id;

  return (
    <div role="treeitem" aria-expanded={expanded} aria-selected={isSelected}>
      <button
        className={cn(
          'flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-sm hover:bg-[var(--muted)]',
          isSelected && 'bg-[var(--accent)] font-medium',
        )}
        onClick={() => {
          setExpanded(!expanded);
          onSelect(folder);
        }}
        aria-label={`${folder.dir_name}, folder${folder.highest_risk_tier ? `, risk: ${folder.highest_risk_tier}` : ''}`}
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />}
        <FolderOpen className="h-4 w-4 text-yellow-500" aria-hidden="true" />
        <span className="truncate">{folder.dir_name}</span>
        {folder.highest_risk_tier && <RiskBadge tier={folder.highest_risk_tier as RiskTier} className="ml-auto text-[10px]" />}
      </button>
      {expanded && childFolders.length > 0 && (
        <div className="ml-4 border-l pl-1" role="group">
          {childFolders.map((child) => (
            <FolderTreeItem key={child.id} folder={child} targetId={targetId} onSelect={onSelect} selectedId={selectedId} />
          ))}
        </div>
      )}
    </div>
  );
}

export function Component() {
  const targets = useTargets();
  const [targetId, setTargetId] = useState<string>('');
  const [selectedFolder, setSelectedFolder] = useState<BrowseFolder | null>(null);

  const rootEntries = useQuery({
    queryKey: ['browse', targetId],
    queryFn: () => browseApi.list(targetId),
    enabled: !!targetId,
  });

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left: Folder tree */}
      <div className="flex w-72 flex-col border-r">
        <div className="border-b p-3">
          <Select value={targetId} onValueChange={setTargetId}>
            <SelectTrigger aria-label="Select target"><SelectValue placeholder="Select target" /></SelectTrigger>
            <SelectContent>
              {(targets.data?.items ?? []).map((t) => (
                <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex-1 overflow-y-auto p-2" role="tree" aria-label="File explorer">
          {rootEntries.isLoading ? (
            <div className="space-y-1">
              {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-7 w-full" />)}
            </div>
          ) : rootEntries.isError ? (
            <div className="flex flex-col items-center gap-2 p-4 text-center text-sm text-[var(--destructive)]">
              <AlertCircle className="h-5 w-5" />
              <p>Failed to load folders</p>
              <button className="text-xs underline" onClick={() => rootEntries.refetch()}>Retry</button>
            </div>
          ) : (
            (rootEntries.data?.folders ?? []).map((folder) => (
              <FolderTreeItem
                key={folder.id}
                folder={folder}
                targetId={targetId}
                onSelect={setSelectedFolder}
                selectedId={selectedFolder?.id ?? null}
              />
            ))
          )}
        </div>
      </div>

      {/* Center: Details for selected folder */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {selectedFolder ? (
          <SelectedFolderPanel folder={selectedFolder} />
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-[var(--muted-foreground)]">
            Select a folder to view its details
          </div>
        )}
      </div>
    </div>
  );
}

function SelectedFolderPanel({ folder }: { folder: BrowseFolder }) {
  return (
    <div className="flex-1 overflow-y-auto p-6">
      <Card>
        <CardHeader><CardTitle>{folder.dir_name}</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-[var(--muted-foreground)]">{folder.dir_path}</p>
          {folder.highest_risk_tier && <RiskBadge tier={folder.highest_risk_tier as RiskTier} />}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-[var(--muted-foreground)]">Child Folders</p>
              <p className="font-medium">{folder.child_dir_count ?? 0}</p>
            </div>
            <div>
              <p className="text-[var(--muted-foreground)]">Child Files</p>
              <p className="font-medium">{folder.child_file_count ?? 0}</p>
            </div>
            <div>
              <p className="text-[var(--muted-foreground)]">Entities Found</p>
              <p className="font-medium">{folder.total_entities_found ?? 0}</p>
            </div>
            <div>
              <p className="text-[var(--muted-foreground)]">Last Scanned</p>
              <p className="font-medium">{folder.last_scanned_at ?? '—'}</p>
            </div>
          </div>
          {(folder.world_accessible || folder.authenticated_users) && (
            <div className="mt-2 space-y-1">
              {folder.world_accessible && (
                <p className="text-xs font-medium text-red-600">World Accessible</p>
              )}
              {folder.authenticated_users && (
                <p className="text-xs font-medium text-yellow-600">Authenticated Users Access</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
