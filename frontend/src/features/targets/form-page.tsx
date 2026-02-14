import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import { FolderOpen, ChevronRight, ChevronDown } from 'lucide-react';
import { useTarget, useCreateTarget, useUpdateTarget } from '@/api/hooks/use-targets.ts';
import { browseApi } from '@/api/endpoints/browse.ts';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { ADAPTER_TYPES, ADAPTER_LABELS } from '@/lib/constants.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import { cn } from '@/lib/utils.ts';
import type { BrowseFolder } from '@/api/types.ts';

const targetSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  adapter: z.enum(ADAPTER_TYPES),
  enabled: z.boolean(),
  config: z.record(z.string(), z.unknown()),
});

type TargetFormData = z.infer<typeof targetSchema>;

const NON_FS_ADAPTER_FIELDS: Record<string, { key: string; label: string; placeholder: string }[]> = {
  sharepoint: [
    { key: 'site_url', label: 'Site URL', placeholder: 'https://company.sharepoint.com/sites/hr' },
    { key: 'document_libraries', label: 'Document Libraries', placeholder: 'Documents,Shared Documents' },
  ],
  onedrive: [
    { key: 'user_emails', label: 'User Emails', placeholder: 'user@company.com' },
  ],
  s3: [
    { key: 'bucket', label: 'Bucket Name', placeholder: 'my-bucket' },
    { key: 'region', label: 'Region', placeholder: 'us-east-1' },
    { key: 'endpoint_url', label: 'Endpoint URL (optional)', placeholder: '' },
  ],
  gcs: [
    { key: 'bucket', label: 'Bucket Name', placeholder: 'my-bucket' },
    { key: 'project', label: 'Project', placeholder: 'my-project' },
  ],
  azure_blob: [
    { key: 'container', label: 'Container', placeholder: 'my-container' },
    { key: 'storage_account', label: 'Storage Account', placeholder: 'mystorageaccount' },
  ],
};

/* ── Folder picker tree (for editing existing targets) ── */

function PickerTreeItem({ folder, targetId, onSelect, selectedPath }: {
  folder: BrowseFolder;
  targetId: string;
  onSelect: (path: string) => void;
  selectedPath: string;
}) {
  const [expanded, setExpanded] = useState(false);

  const children = useQuery({
    queryKey: ['browse', targetId, folder.id],
    queryFn: () => browseApi.list(targetId, folder.id),
    enabled: expanded,
  });

  const childFolders = children.data?.folders ?? [];
  const isSelected = selectedPath === folder.dir_path;

  return (
    <div>
      <button
        type="button"
        className={cn(
          'flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-sm hover:bg-[var(--muted)]',
          isSelected && 'bg-[var(--accent)] font-medium',
        )}
        onClick={() => {
          setExpanded(!expanded);
          onSelect(folder.dir_path);
        }}
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" />}
        <FolderOpen className="h-4 w-4 text-yellow-500" />
        <span className="truncate">{folder.dir_name}</span>
      </button>
      {expanded && childFolders.length > 0 && (
        <div className="ml-4 border-l pl-1">
          {childFolders.map((child) => (
            <PickerTreeItem key={child.id} folder={child} targetId={targetId} onSelect={onSelect} selectedPath={selectedPath} />
          ))}
        </div>
      )}
    </div>
  );
}

function PathPicker({ targetId, value, onChange }: {
  targetId: string | undefined;
  value: string;
  onChange: (path: string) => void;
}) {
  const rootEntries = useQuery({
    queryKey: ['browse', targetId],
    queryFn: () => browseApi.list(targetId!),
    enabled: !!targetId,
  });

  if (!targetId) {
    return (
      <div>
        <Label htmlFor="root_path">Root Path</Label>
        <Input
          id="root_path"
          placeholder="/mnt/shares/data"
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
        <p className="mt-1 text-xs text-[var(--muted-foreground)]">Save the target first to browse available paths</p>
      </div>
    );
  }

  return (
    <div>
      <Label>Root Path</Label>
      {value && (
        <p className="mb-2 rounded bg-[var(--muted)] px-3 py-1.5 text-sm font-mono">{value}</p>
      )}
      <div className="max-h-64 overflow-y-auto rounded-md border p-2">
        {rootEntries.isLoading ? (
          <div className="space-y-1">
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-7 w-full" />)}
          </div>
        ) : (rootEntries.data?.folders ?? []).length === 0 ? (
          <p className="p-2 text-sm text-[var(--muted-foreground)]">No directories found. Run a scan to populate the tree.</p>
        ) : (
          (rootEntries.data?.folders ?? []).map((folder) => (
            <PickerTreeItem
              key={folder.id}
              folder={folder}
              targetId={targetId}
              onSelect={onChange}
              selectedPath={value}
            />
          ))
        )}
      </div>
    </div>
  );
}

/* ── Main form ── */

export function Component() {
  const { targetId } = useParams<{ targetId: string }>();
  const navigate = useNavigate();
  const isEdit = !!targetId;
  const target = useTarget(targetId ?? '');
  const createTarget = useCreateTarget();
  const updateTarget = useUpdateTarget();
  const addToast = useUIStore((s) => s.addToast);

  const defaultVals: TargetFormData = { name: '', adapter: 'filesystem', enabled: true, config: {} };
  const targetValues: TargetFormData | undefined = target.data
    ? { name: target.data.name, adapter: target.data.adapter as TargetFormData['adapter'], enabled: target.data.enabled, config: target.data.config as Record<string, unknown> }
    : undefined;

  const form = useForm<TargetFormData>({
    resolver: zodResolver(targetSchema),
    defaultValues: targetValues ?? defaultVals,
    values: isEdit ? targetValues : undefined,
  });

  if (isEdit && target.isLoading) return <LoadingSkeleton />;

  const adapterType = form.watch('adapter');
  const config = form.watch('config');
  const isLocal = config.is_local === true;
  const isFilesystem = adapterType === 'filesystem';
  const nonFsFields = NON_FS_ADAPTER_FIELDS[adapterType] ?? [];

  const setConfigField = (key: string, value: unknown) => {
    form.setValue('config', { ...form.getValues('config'), [key]: value });
  };

  const onSubmit = (data: TargetFormData) => {
    if (isEdit) {
      updateTarget.mutate({ id: targetId!, ...data }, {
        onSuccess: () => { addToast({ level: 'success', message: 'Target updated' }); navigate('/targets'); },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    } else {
      createTarget.mutate(data, {
        onSuccess: () => { addToast({ level: 'success', message: 'Target created' }); navigate('/targets'); },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold">{isEdit ? 'Edit Target' : 'New Target'}</h1>

      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader><CardTitle>General</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input id="name" aria-describedby={form.formState.errors.name ? 'name-error' : undefined} aria-invalid={!!form.formState.errors.name} {...form.register('name')} />
              {form.formState.errors.name && (
                <p id="name-error" role="alert" className="mt-1 text-xs text-red-500">{form.formState.errors.name.message}</p>
              )}
            </div>

            <div>
              <Label htmlFor="adapter">Adapter</Label>
              <Select value={adapterType} onValueChange={(v) => form.setValue('adapter', v as typeof adapterType)}>
                <SelectTrigger id="adapter"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ADAPTER_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>{ADAPTER_LABELS[t]}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <label className="flex items-center gap-2">
              <input type="checkbox" {...form.register('enabled')} className="rounded" />
              <span className="text-sm">Enabled</span>
            </label>
          </CardContent>
        </Card>

        {isFilesystem && (
          <Card>
            <CardHeader><CardTitle>Adapter Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {/* Resource selector */}
              <div>
                <Label htmlFor="resource">Resource</Label>
                <div className="flex items-center gap-3">
                  <label className="flex shrink-0 items-center gap-2">
                    <input
                      type="checkbox"
                      checked={isLocal}
                      onChange={(e) => {
                        setConfigField('is_local', e.target.checked);
                        if (e.target.checked) setConfigField('resource', 'localhost');
                      }}
                      className="rounded"
                    />
                    <span className="text-sm">Local</span>
                  </label>
                  <Input
                    id="resource"
                    placeholder="hostname or IP address"
                    value={(config.resource as string) ?? ''}
                    onChange={(e) => setConfigField('resource', e.target.value)}
                    disabled={isLocal}
                  />
                </div>
                <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                  DNS name or IP address of the target server, or select Local
                </p>
              </div>

              {/* Root path tree picker */}
              <PathPicker
                targetId={isEdit ? targetId : undefined}
                value={(config.root_path as string) ?? ''}
                onChange={(path) => setConfigField('root_path', path)}
              />

              {/* Extensions */}
              <div>
                <Label htmlFor="extensions">File Extensions</Label>
                <Input
                  id="extensions"
                  placeholder=".docx,.xlsx,.pdf"
                  value={(config.extensions as string) ?? ''}
                  onChange={(e) => setConfigField('extensions', e.target.value)}
                />
              </div>

              {/* Exclude patterns */}
              <div>
                <Label htmlFor="exclude_patterns">Exclude Patterns</Label>
                <Input
                  id="exclude_patterns"
                  placeholder="*.tmp,~$*"
                  value={(config.exclude_patterns as string) ?? ''}
                  onChange={(e) => setConfigField('exclude_patterns', e.target.value)}
                />
              </div>

              {/* Apply MIP Labels */}
              <label className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  checked={config.apply_mip_labels === true}
                  onChange={(e) => setConfigField('apply_mip_labels', e.target.checked)}
                  className="rounded"
                />
                <span className="text-sm">Apply MIP Labels</span>
              </label>
            </CardContent>
          </Card>
        )}

        {!isFilesystem && nonFsFields.length > 0 && (
          <Card>
            <CardHeader><CardTitle>Adapter Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {nonFsFields.map((field) => (
                <div key={field.key}>
                  <Label htmlFor={field.key}>{field.label}</Label>
                  <Input
                    id={field.key}
                    placeholder={field.placeholder}
                    value={(config[field.key] as string) ?? ''}
                    onChange={(e) => setConfigField(field.key, e.target.value)}
                  />
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        <div className="flex gap-3">
          <Button type="submit" disabled={createTarget.isPending || updateTarget.isPending}>
            {isEdit ? 'Save Changes' : 'Create Target'}
          </Button>
          <Button type="button" variant="outline" onClick={() => navigate('/targets')}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}
