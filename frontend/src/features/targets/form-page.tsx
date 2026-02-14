import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import {
  FolderOpen, ChevronRight, ChevronDown, Loader2, CheckCircle2,
  AlertCircle, Lock, Eye, EyeOff, Server, Cloud,
} from 'lucide-react';
import { useTarget, useCreateTarget, useUpdateTarget } from '@/api/hooks/use-targets.ts';
import { useStoreCredentials, useEnumerate } from '@/api/hooks/use-credentials.ts';
import { browseApi } from '@/api/endpoints/browse.ts';
import type { EnumeratedResource } from '@/api/endpoints/enumerate.ts';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import {
  ADAPTER_TYPES,
  SOURCE_TYPES, SOURCE_LABELS, SOURCE_DESCRIPTIONS,
  SOURCE_CREDENTIAL_FIELDS,
  sourceToAdapter,
  type SourceType,
} from '@/lib/constants.ts';
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

/* ── Source type radio selector ── */

function SourceTypeSelector({ value, onChange }: {
  value: SourceType;
  onChange: (v: SourceType) => void;
}) {
  return (
    <div className="space-y-2">
      <Label>Source Type</Label>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        {SOURCE_TYPES.map((st) => {
          const isSelected = value === st;
          const isFs = st === 'smb' || st === 'nfs';
          return (
            <button
              key={st}
              type="button"
              className={cn(
                'flex flex-col items-start gap-1 rounded-lg border-2 p-3 text-left transition-all',
                isSelected
                  ? 'border-primary-600 bg-primary-600/5'
                  : 'border-[var(--border)] hover:border-[var(--muted-foreground)]/50',
              )}
              onClick={() => onChange(st)}
            >
              <div className="flex items-center gap-2">
                {isFs ? (
                  <Server className="h-4 w-4 text-[var(--muted-foreground)]" />
                ) : (
                  <Cloud className="h-4 w-4 text-[var(--muted-foreground)]" />
                )}
                <span className="text-sm font-semibold">{SOURCE_LABELS[st]}</span>
              </div>
              <span className="text-xs text-[var(--muted-foreground)]">{SOURCE_DESCRIPTIONS[st]}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ── Credential entry form ── */

function CredentialForm({ sourceType, credentials, onChange, onConnect, isConnecting, saveCredentials, onSaveChange }: {
  sourceType: SourceType;
  credentials: Record<string, string>;
  onChange: (creds: Record<string, string>) => void;
  onConnect: () => void;
  isConnecting: boolean;
  saveCredentials: boolean;
  onSaveChange: (v: boolean) => void;
}) {
  const fields = SOURCE_CREDENTIAL_FIELDS[sourceType] ?? [];
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});

  if (fields.length === 0) return null;

  const isLocalHost = (sourceType === 'smb' || sourceType === 'nfs') &&
    ['localhost', '127.0.0.1', '::1', ''].includes(credentials.host?.trim() ?? '');

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Lock className="h-4 w-4 text-[var(--muted-foreground)]" />
        <Label className="text-base font-semibold">Credentials</Label>
      </div>

      {/* Local option for SMB/NFS */}
      {(sourceType === 'smb' || sourceType === 'nfs') && (
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={isLocalHost}
            onChange={(e) => {
              if (e.target.checked) {
                onChange({ ...credentials, host: 'localhost' });
              } else {
                onChange({ ...credentials, host: '' });
              }
            }}
            className="rounded"
          />
          <span className="text-sm">Local machine</span>
        </label>
      )}

      {fields.map((field) => {
        const isPassword = field.type === 'password';
        const isTextarea = field.type === 'textarea';
        const isVisible = showPasswords[field.key];

        // Skip username/password for local SMB/NFS
        if (isLocalHost && (field.key === 'username' || field.key === 'password')) {
          return null;
        }

        return (
          <div key={field.key}>
            <Label htmlFor={`cred-${field.key}`}>{field.label}</Label>
            {isTextarea ? (
              <textarea
                id={`cred-${field.key}`}
                className="mt-1 block w-full rounded-md border bg-[var(--background)] px-3 py-2 text-sm font-mono"
                rows={4}
                placeholder={field.placeholder}
                value={credentials[field.key] ?? ''}
                onChange={(e) => onChange({ ...credentials, [field.key]: e.target.value })}
              />
            ) : (
              <div className="relative">
                <Input
                  id={`cred-${field.key}`}
                  type={isPassword && !isVisible ? 'password' : 'text'}
                  placeholder={field.placeholder}
                  value={credentials[field.key] ?? ''}
                  onChange={(e) => onChange({ ...credentials, [field.key]: e.target.value })}
                />
                {isPassword && (
                  <button
                    type="button"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                    onClick={() => setShowPasswords((p) => ({ ...p, [field.key]: !p[field.key] }))}
                  >
                    {isVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                )}
              </div>
            )}
          </div>
        );
      })}

      <div className="flex items-center justify-between pt-2">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={saveCredentials}
            onChange={(e) => onSaveChange(e.target.checked)}
            className="rounded"
          />
          <span className="text-sm">Save credentials for this session</span>
        </label>
        <Button
          type="button"
          onClick={onConnect}
          disabled={isConnecting}
        >
          {isConnecting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Connecting...
            </>
          ) : (
            'Connect & Browse'
          )}
        </Button>
      </div>
    </div>
  );
}

/* ── Resource selection list ── */

function ResourceSelector({ resources, selected, onToggle, onSelectAll }: {
  resources: EnumeratedResource[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  onSelectAll: (all: boolean) => void;
}) {
  if (resources.length === 0) {
    return (
      <p className="py-4 text-center text-sm text-[var(--muted-foreground)]">
        No resources found. Check your credentials or connection.
      </p>
    );
  }

  const allSelected = resources.every((r) => selected.has(r.id));

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <Label className="text-base font-semibold">
          Select Resources to Monitor ({selected.size} of {resources.length})
        </Label>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onSelectAll(!allSelected)}
        >
          {allSelected ? 'Deselect All' : 'Select All'}
        </Button>
      </div>
      <div className="max-h-64 space-y-1 overflow-y-auto rounded-md border p-2">
        {resources.map((resource) => (
          <label
            key={resource.id}
            className={cn(
              'flex cursor-pointer items-start gap-3 rounded-md px-3 py-2 transition-colors hover:bg-[var(--muted)]',
              selected.has(resource.id) && 'bg-[var(--accent)]',
            )}
          >
            <input
              type="checkbox"
              className="mt-0.5 rounded"
              checked={selected.has(resource.id)}
              onChange={() => onToggle(resource.id)}
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{resource.name}</span>
                <span className="rounded bg-[var(--muted)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--muted-foreground)]">
                  {resource.resource_type}
                </span>
              </div>
              <p className="truncate text-xs text-[var(--muted-foreground)]">{resource.path}</p>
              {resource.description && (
                <p className="text-xs text-[var(--muted-foreground)]">{resource.description}</p>
              )}
            </div>
          </label>
        ))}
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
  const storeCreds = useStoreCredentials();
  const enumerate = useEnumerate();
  const addToast = useUIStore((s) => s.addToast);

  // Source type (UI-level — maps to backend adapter type)
  const [sourceType, setSourceType] = useState<SourceType>('smb');

  // Credentials
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [saveCredentials, setSaveCredentials] = useState(false);

  // Enumerated resources
  const [enumeratedResources, setEnumeratedResources] = useState<EnumeratedResource[]>([]);
  const [selectedResources, setSelectedResources] = useState<Set<string>>(new Set());
  const [hasEnumerated, setHasEnumerated] = useState(false);
  const [enumError, setEnumError] = useState<string | null>(null);

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

  const config = form.watch('config');

  const setConfigField = (key: string, value: unknown) => {
    form.setValue('config', { ...form.getValues('config'), [key]: value });
  };

  const handleSourceTypeChange = (newType: SourceType) => {
    setSourceType(newType);
    // Update the backend adapter type
    form.setValue('adapter', sourceToAdapter(newType));
    // Reset enumeration state
    setEnumeratedResources([]);
    setSelectedResources(new Set());
    setHasEnumerated(false);
    setEnumError(null);
    setCredentials({});
    // Store source_type in config so backend knows which protocol
    form.setValue('config', { source_type: newType });
  };

  const handleConnect = async () => {
    setEnumError(null);

    // Optionally save credentials first
    if (saveCredentials) {
      try {
        await storeCreds.mutateAsync({
          source_type: sourceType,
          credentials,
          save: true,
        });
      } catch (err) {
        addToast({ level: 'error', message: `Failed to save credentials: ${(err as Error).message}` });
      }
    }

    // Enumerate
    try {
      const result = await enumerate.mutateAsync({
        source_type: sourceType,
        credentials,
      });
      setEnumeratedResources(result.resources);
      setHasEnumerated(true);
      // Auto-select all by default
      setSelectedResources(new Set(result.resources.map((r) => r.id)));
      if (result.resources.length === 0) {
        setEnumError('Connected successfully but no resources were found.');
      }
    } catch (err) {
      const msg = (err as Error).message || 'Connection failed';
      setEnumError(msg);
      addToast({ level: 'error', message: msg });
    }
  };

  const handleToggleResource = (id: string) => {
    setSelectedResources((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectAll = (all: boolean) => {
    if (all) {
      setSelectedResources(new Set(enumeratedResources.map((r) => r.id)));
    } else {
      setSelectedResources(new Set());
    }
  };

  const onSubmit = (data: TargetFormData) => {
    // Merge selected resources into config
    const selectedItems = enumeratedResources.filter((r) => selectedResources.has(r.id));
    const finalConfig = {
      ...data.config,
      source_type: sourceType,
      selected_resources: selectedItems.map((r) => ({
        id: r.id,
        name: r.name,
        path: r.path,
        resource_type: r.resource_type,
      })),
    };

    // For SMB/NFS, set the host and path from credentials
    if (sourceType === 'smb' || sourceType === 'nfs') {
      const host = credentials.host?.trim() || 'localhost';
      const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1';
      finalConfig.resource = host;
      finalConfig.is_local = isLocal;
      // If only one resource selected and it has a path, use as root_path
      if (selectedItems.length === 1) {
        finalConfig.root_path = selectedItems[0].path;
        // For filesystem adapter, set 'path' which the backend validator expects
        finalConfig.path = selectedItems[0].path;
      } else if (selectedItems.length > 0) {
        // Find common parent or use first path
        finalConfig.root_path = selectedItems[0].path;
        finalConfig.path = selectedItems[0].path;
      }
    }

    // For cloud sources, set relevant config fields from credentials/selection
    if (sourceType === 'sharepoint') {
      if (selectedItems.length > 0) {
        finalConfig.site_url = selectedItems[0].path;
        finalConfig.document_libraries = selectedItems.map((r) => r.name).join(',');
      }
    } else if (sourceType === 'onedrive') {
      if (selectedItems.length > 0) {
        finalConfig.user_emails = selectedItems.map((r) => r.path).join(',');
        finalConfig.user_id = selectedItems[0].id;
      }
    } else if (sourceType === 's3') {
      if (selectedItems.length > 0) {
        finalConfig.bucket = selectedItems[0].name;
      }
      finalConfig.region = credentials.region || 'us-east-1';
      if (credentials.endpoint_url) finalConfig.endpoint_url = credentials.endpoint_url;
    } else if (sourceType === 'gcs') {
      if (selectedItems.length > 0) {
        finalConfig.bucket = selectedItems[0].name;
      }
      if (credentials.project) finalConfig.project = credentials.project;
    } else if (sourceType === 'azure_blob') {
      if (selectedItems.length > 0) {
        finalConfig.container = selectedItems[0].name;
      }
      if (credentials.storage_account) finalConfig.storage_account = credentials.storage_account;
    }

    const submitData = { ...data, config: finalConfig };

    if (isEdit) {
      updateTarget.mutate({ id: targetId!, ...submitData }, {
        onSuccess: () => { addToast({ level: 'success', message: 'Resource updated' }); navigate('/targets'); },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    } else {
      createTarget.mutate(submitData, {
        onSuccess: () => { addToast({ level: 'success', message: 'Resource created' }); navigate('/targets'); },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold">{isEdit ? 'Edit Resource' : 'Add Resource'}</h1>

      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        {/* General */}
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
            <label className="flex items-center gap-2">
              <input type="checkbox" {...form.register('enabled')} className="rounded" />
              <span className="text-sm">Enabled</span>
            </label>
          </CardContent>
        </Card>

        {/* Resource — source type + credentials + enumeration */}
        <Card>
          <CardHeader><CardTitle>Resource</CardTitle></CardHeader>
          <CardContent className="space-y-6">
            <SourceTypeSelector value={sourceType} onChange={handleSourceTypeChange} />

            <div className="border-t pt-4">
              <CredentialForm
                sourceType={sourceType}
                credentials={credentials}
                onChange={setCredentials}
                onConnect={handleConnect}
                isConnecting={enumerate.isPending}
                saveCredentials={saveCredentials}
                onSaveChange={setSaveCredentials}
              />
            </div>

            {/* Connection status */}
            {enumerate.isPending && (
              <div className="flex items-center gap-2 rounded-md bg-blue-50 px-4 py-3 text-sm text-blue-700">
                <Loader2 className="h-4 w-4 animate-spin" />
                Connecting and enumerating resources...
              </div>
            )}
            {enumError && !enumerate.isPending && (
              <div className="flex items-center gap-2 rounded-md bg-red-50 px-4 py-3 text-sm text-red-700">
                <AlertCircle className="h-4 w-4" />
                {enumError}
              </div>
            )}
            {hasEnumerated && enumeratedResources.length > 0 && !enumerate.isPending && (
              <div className="flex items-center gap-2 rounded-md bg-green-50 px-4 py-3 text-sm text-green-700">
                <CheckCircle2 className="h-4 w-4" />
                Connected — {enumeratedResources.length} resource{enumeratedResources.length !== 1 ? 's' : ''} found
              </div>
            )}

            {/* Resource selection */}
            {hasEnumerated && (
              <div className="border-t pt-4">
                <ResourceSelector
                  resources={enumeratedResources}
                  selected={selectedResources}
                  onToggle={handleToggleResource}
                  onSelectAll={handleSelectAll}
                />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Filtering & Labels — always shown after source type is chosen */}
        <Card>
          <CardHeader><CardTitle>Filtering &amp; Labels</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            {/* File Extensions */}
            <div>
              <Label htmlFor="extensions">File Extensions</Label>
              <Input
                id="extensions"
                placeholder=".docx,.xlsx,.pdf"
                value={(config.extensions as string) ?? ''}
                onChange={(e) => setConfigField('extensions', e.target.value)}
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                Comma-separated list. Leave empty to scan all supported types.
              </p>
            </div>

            {/* Exclude patterns */}
            <div>
              <Label htmlFor="exclude_patterns">Exclude Patterns</Label>
              <Input
                id="exclude_patterns"
                placeholder="*.tmp,~$*,*.log"
                value={(config.exclude_patterns as string) ?? ''}
                onChange={(e) => setConfigField('exclude_patterns', e.target.value)}
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                Glob patterns to exclude files from scanning (comma-separated).
              </p>
            </div>

            {/* Root path for editing existing FS targets */}
            {isEdit && (sourceType === 'smb' || sourceType === 'nfs') && (
              <PathPicker
                targetId={targetId}
                value={(config.root_path as string) ?? ''}
                onChange={(path) => setConfigField('root_path', path)}
              />
            )}

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

        <div className="flex gap-3">
          <Button type="submit" disabled={createTarget.isPending || updateTarget.isPending}>
            {isEdit ? 'Save Changes' : 'Create Resource'}
          </Button>
          <Button type="button" variant="outline" onClick={() => navigate('/targets')}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}
