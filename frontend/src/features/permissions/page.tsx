import { useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Lock, Unlock, Eye } from 'lucide-react';
import { useDirectoryACL } from '@/api/hooks/use-permissions.ts';
import { FolderTreePanel } from '@/components/folder-tree.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { EmptyState } from '@/components/empty-state.tsx';
import type { BrowseFolder } from '@/api/types.ts';

const EXPOSURE_COLORS: Record<string, string> = {
  PUBLIC: 'bg-red-100 text-red-800',
  ORG_WIDE: 'bg-orange-100 text-orange-800',
  INTERNAL: 'bg-yellow-100 text-yellow-800',
  PRIVATE: 'bg-green-100 text-green-800',
};

function ACLPanel({ targetId, folder }: { targetId: string; folder: BrowseFolder }) {
  const acl = useDirectoryACL(targetId, folder.id);

  // Derive exposure from folder data
  const hasSD = folder.world_accessible != null || folder.authenticated_users != null || folder.custom_acl != null;
  const isOpenAccess = folder.world_accessible || folder.authenticated_users;
  const isProtected = hasSD && !isOpenAccess;

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-4">
      {/* Folder header */}
      <div>
        <h2 className="text-lg font-semibold">{folder.dir_name}</h2>
        <p className="text-sm text-[var(--muted-foreground)]">{folder.dir_path}</p>
      </div>

      {/* Insight cards */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Eye className="h-5 w-5 text-[var(--muted-foreground)]" />
            <div>
              <p className="text-2xl font-bold">{folder.total_entities_found ?? 0}</p>
              <p className="text-xs text-[var(--muted-foreground)]">Sensitive Entities</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            {isProtected ? (
              <ShieldCheck className="h-5 w-5 text-green-600" />
            ) : (
              <ShieldAlert className="h-5 w-5 text-yellow-600" />
            )}
            <div>
              <p className="text-sm font-semibold">{isProtected ? 'Protected' : hasSD ? 'Exposed' : 'No SD'}</p>
              <p className="text-xs text-[var(--muted-foreground)]">Security Status</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            {isOpenAccess ? (
              <Unlock className="h-5 w-5 text-red-600" />
            ) : (
              <Lock className="h-5 w-5 text-green-600" />
            )}
            <div>
              <p className="text-sm font-semibold">{isOpenAccess ? 'Open Access' : 'Restricted'}</p>
              <p className="text-xs text-[var(--muted-foreground)]">
                {folder.world_accessible ? 'World Accessible' : folder.authenticated_users ? 'Auth Users' : 'Private'}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ACL detail */}
      {acl.isLoading ? (
        <Skeleton className="h-48" />
      ) : acl.data ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Access Control List
              {acl.data.exposure_level && (
                <Badge className={EXPOSURE_COLORS[acl.data.exposure_level] ?? ''}>{acl.data.exposure_level}</Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[var(--muted-foreground)]">Owner</p>
                <p className="font-mono">{acl.data.owner_sid ?? '—'}</p>
              </div>
              <div>
                <p className="text-[var(--muted-foreground)]">Group</p>
                <p className="font-mono">{acl.data.group_sid ?? '—'}</p>
              </div>
            </div>
            {acl.data.dacl_sddl && (
              <div>
                <p className="text-[var(--muted-foreground)]">DACL (SDDL)</p>
                <pre className="mt-1 overflow-x-auto rounded-md bg-[var(--muted)] p-3 text-xs">{acl.data.dacl_sddl}</pre>
              </div>
            )}
            {acl.data.permissions_json && Object.keys(acl.data.permissions_json).length > 0 && (
              <div>
                <p className="text-[var(--muted-foreground)]">Permissions</p>
                <pre className="mt-1 overflow-x-auto rounded-md bg-[var(--muted)] p-3 text-xs">
                  {JSON.stringify(acl.data.permissions_json, null, 2)}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-6 text-center text-sm text-[var(--muted-foreground)]">
            No security descriptor available for this directory
          </CardContent>
        </Card>
      )}
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
          <ACLPanel targetId={targetId} folder={selectedFolder} />
        ) : (
          <EmptyState icon={Shield} title="Select a folder" description="Click a path in the tree to view its ACL and security insights" />
        )}
      </div>
    </div>
  );
}
