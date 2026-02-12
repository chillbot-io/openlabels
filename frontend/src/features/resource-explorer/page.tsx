import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FolderOpen, File, ChevronRight, ChevronDown } from 'lucide-react';
import { browseApi } from '@/api/endpoints/browse.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { EntityTag } from '@/components/entity-tag.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { cn } from '@/lib/utils.ts';
import type { DirectoryEntry } from '@/api/types.ts';
import type { RiskTier } from '@/lib/constants.ts';

function FolderTreeItem({ entry, targetId, onSelect, selectedId }: {
  entry: DirectoryEntry;
  targetId: string;
  onSelect: (entry: DirectoryEntry) => void;
  selectedId: string | null;
}) {
  const [expanded, setExpanded] = useState(false);

  const children = useQuery({
    queryKey: ['browse', targetId, entry.path],
    queryFn: () => browseApi.list(targetId, entry.path),
    enabled: expanded && entry.is_directory,
  });

  const dirs = (children.data ?? []).filter((e) => e.is_directory);
  const isSelected = selectedId === entry.id;

  return (
    <div role="treeitem" aria-expanded={entry.is_directory ? expanded : undefined} aria-selected={isSelected}>
      <button
        className={cn(
          'flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-sm hover:bg-[var(--muted)]',
          isSelected && 'bg-[var(--accent)] font-medium',
        )}
        onClick={() => {
          if (entry.is_directory) setExpanded(!expanded);
          onSelect(entry);
        }}
        aria-label={`${entry.name}${entry.is_directory ? ', folder' : ', file'}${entry.risk_tier ? `, risk: ${entry.risk_tier}` : ''}`}
      >
        {entry.is_directory ? (
          expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        ) : <span className="w-3.5" aria-hidden="true" />}
        {entry.is_directory ? <FolderOpen className="h-4 w-4 text-yellow-500" aria-hidden="true" /> : <File className="h-4 w-4 text-gray-400" aria-hidden="true" />}
        <span className="truncate">{entry.name}</span>
        {entry.risk_tier && <RiskBadge tier={entry.risk_tier as RiskTier} className="ml-auto text-[10px]" />}
      </button>
      {expanded && dirs.length > 0 && (
        <div className="ml-4 border-l pl-1" role="group">
          {dirs.map((child) => (
            <FolderTreeItem key={child.id} entry={child} targetId={targetId} onSelect={onSelect} selectedId={selectedId} />
          ))}
        </div>
      )}
    </div>
  );
}

export function Component() {
  const targets = useTargets();
  const [targetId, setTargetId] = useState<string>('');
  const [selectedEntry, setSelectedEntry] = useState<DirectoryEntry | null>(null);

  const rootEntries = useQuery({
    queryKey: ['browse', targetId, ''],
    queryFn: () => browseApi.list(targetId, ''),
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
          ) : (
            (rootEntries.data ?? []).map((entry) => (
              <FolderTreeItem
                key={entry.id}
                entry={entry}
                targetId={targetId}
                onSelect={setSelectedEntry}
                selectedId={selectedEntry?.id ?? null}
              />
            ))
          )}
        </div>
      </div>

      {/* Center: File list for selected directory */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {selectedEntry ? (
          <SelectedEntryPanel entry={selectedEntry} targetId={targetId} />
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-[var(--muted-foreground)]">
            Select a folder to view its contents
          </div>
        )}
      </div>
    </div>
  );
}

function SelectedEntryPanel({ entry, targetId }: { entry: DirectoryEntry; targetId: string }) {
  const children = useQuery({
    queryKey: ['browse', targetId, entry.path, 'children'],
    queryFn: () => browseApi.list(targetId, entry.path),
    enabled: entry.is_directory,
  });

  if (!entry.is_directory) {
    return (
      <div className="flex-1 overflow-y-auto p-6">
        <Card>
          <CardHeader><CardTitle>{entry.name}</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-[var(--muted-foreground)]">{entry.path}</p>
            {entry.risk_tier && <RiskBadge tier={entry.risk_tier as RiskTier} />}
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-[var(--muted-foreground)]">File Size</p>
                <p className="font-medium">{entry.file_size?.toLocaleString() ?? '—'} bytes</p>
              </div>
              <div>
                <p className="text-[var(--muted-foreground)]">Entities Found</p>
                <p className="font-medium">{entry.entity_count}</p>
              </div>
              <div>
                <p className="text-[var(--muted-foreground)]">Risk Score</p>
                <p className="font-medium">{entry.risk_score ?? '—'}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const files = (children.data ?? []).filter((e) => !e.is_directory);

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <h2 className="mb-4 text-lg font-semibold">{entry.name}</h2>
      <p className="mb-4 text-sm text-[var(--muted-foreground)]">{entry.path} &mdash; {files.length} files</p>
      {children.isLoading ? (
        <Skeleton className="h-48" />
      ) : (
        <div className="space-y-1">
          {files.map((file) => (
            <div key={file.id} className="flex items-center justify-between rounded-md px-3 py-2 hover:bg-[var(--muted)]">
              <div className="flex items-center gap-2">
                <File className="h-4 w-4 text-gray-400" />
                <span className="text-sm">{file.name}</span>
              </div>
              <div className="flex items-center gap-2">
                {file.entity_count > 0 && <EntityTag type="entities" count={file.entity_count} />}
                {file.risk_tier && <RiskBadge tier={file.risk_tier as RiskTier} />}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
