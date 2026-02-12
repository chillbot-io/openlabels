import { useNavigate, useParams } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useTarget, useCreateTarget, useUpdateTarget } from '@/api/hooks/use-targets.ts';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { ADAPTER_TYPES, ADAPTER_LABELS } from '@/lib/constants.ts';
import { useUIStore } from '@/stores/ui-store.ts';

const targetSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  adapter: z.enum(ADAPTER_TYPES),
  enabled: z.boolean(),
  config: z.record(z.string(), z.unknown()),
});

type TargetFormData = z.infer<typeof targetSchema>;

const ADAPTER_FIELDS: Record<string, { key: string; label: string; placeholder: string }[]> = {
  filesystem: [
    { key: 'root_path', label: 'Root Path', placeholder: 'C:\\Shares\\Finance' },
    { key: 'extensions', label: 'File Extensions', placeholder: '.docx,.xlsx,.pdf' },
    { key: 'exclude_patterns', label: 'Exclude Patterns', placeholder: '*.tmp,~$*' },
  ],
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
  const fields = ADAPTER_FIELDS[adapterType] ?? [];

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
              <Input id="name" {...form.register('name')} />
              {form.formState.errors.name && (
                <p className="mt-1 text-xs text-red-500">{form.formState.errors.name.message}</p>
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

        {fields.length > 0 && (
          <Card>
            <CardHeader><CardTitle>Adapter Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {fields.map((field) => (
                <div key={field.key}>
                  <Label htmlFor={field.key}>{field.label}</Label>
                  <Input
                    id={field.key}
                    placeholder={field.placeholder}
                    value={(form.watch('config')[field.key] as string) ?? ''}
                    onChange={(e) => {
                      const config = { ...form.getValues('config'), [field.key]: e.target.value };
                      form.setValue('config', config);
                    }}
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
