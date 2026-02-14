import { useNavigate, useParams } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useSchedule, useCreateSchedule, useUpdateSchedule } from '@/api/hooks/use-schedules.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { describeCron } from '@/lib/date.ts';
import { useUIStore } from '@/stores/ui-store.ts';

const scheduleSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  cron: z.string().min(1, 'Cron expression is required').regex(
    /^(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)$/,
    'Invalid cron expression (expected 5 fields: min hour day month weekday)',
  ),
  target_id: z.string().min(1, 'Select a resource'),
  enabled: z.boolean(),
  exclude_paths: z.string(),
  exclude_file_types: z.string(),
});

type FormData = z.infer<typeof scheduleSchema>;

export function Component() {
  const { scheduleId } = useParams<{ scheduleId: string }>();
  const navigate = useNavigate();
  const isEdit = !!scheduleId;
  const schedule = useSchedule(scheduleId ?? '');
  const targets = useTargets();
  const createSchedule = useCreateSchedule();
  const updateSchedule = useUpdateSchedule();
  const addToast = useUIStore((s) => s.addToast);

  const form = useForm<FormData>({
    resolver: zodResolver(scheduleSchema),
    defaultValues: {
      name: '',
      cron: '0 2 * * 1',
      target_id: '',
      enabled: true,
      exclude_paths: '',
      exclude_file_types: '',
    },
    values: schedule.data
      ? {
          name: schedule.data.name,
          cron: schedule.data.cron ?? '',
          target_id: schedule.data.target_id,
          enabled: schedule.data.enabled,
          exclude_paths: '',
          exclude_file_types: '',
        }
      : undefined,
  });

  if (isEdit && schedule.isLoading) return <LoadingSkeleton />;

  const cronValue = form.watch('cron');
  const cronDescription = describeCron(cronValue);

  const onSubmit = (data: FormData) => {
    const payload = {
      name: data.name,
      cron: data.cron,
      target_id: data.target_id,
      enabled: data.enabled,
    };

    if (isEdit) {
      updateSchedule.mutate(
        { id: scheduleId!, ...payload },
        {
          onSuccess: () => {
            addToast({ level: 'success', message: 'Scan schedule updated' });
            navigate('/scan-config');
          },
          onError: (err) => addToast({ level: 'error', message: err.message }),
        },
      );
    } else {
      createSchedule.mutate(payload, {
        onSuccess: () => {
          addToast({ level: 'success', message: 'Scan schedule created' });
          navigate('/scan-config');
        },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold">{isEdit ? 'Edit Scan Schedule' : 'Create Scan Schedule'}</h1>

      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="name">Schedule Name</Label>
              <Input
                id="name"
                aria-invalid={!!form.formState.errors.name}
                {...form.register('name')}
              />
              {form.formState.errors.name && (
                <p role="alert" className="mt-1 text-xs text-red-500">
                  {form.formState.errors.name.message}
                </p>
              )}
            </div>
            <label className="flex items-center gap-2">
              <input type="checkbox" {...form.register('enabled')} className="rounded" />
              <span className="text-sm">Enabled</span>
            </label>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Resource</CardTitle>
          </CardHeader>
          <CardContent>
            <Label htmlFor="target_id">Select Resource</Label>
            <Select
              value={form.watch('target_id')}
              onValueChange={(v) => form.setValue('target_id', v, { shouldValidate: true })}
            >
              <SelectTrigger id="target_id" aria-invalid={!!form.formState.errors.target_id}>
                <SelectValue placeholder="Choose a resource to scan" />
              </SelectTrigger>
              <SelectContent>
                {(targets.data?.items ?? []).map((target) => (
                  <SelectItem key={target.id} value={target.id}>
                    {target.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {form.formState.errors.target_id && (
              <p role="alert" className="mt-1 text-xs text-red-500">
                {form.formState.errors.target_id.message}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Frequency and Timing</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="cron">Cron Expression</Label>
              <Input
                id="cron"
                aria-invalid={!!form.formState.errors.cron}
                {...form.register('cron')}
                placeholder="0 2 * * 1"
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">{cronDescription.join(' | ')}</p>
              {form.formState.errors.cron && (
                <p role="alert" className="mt-1 text-xs text-red-500">
                  {form.formState.errors.cron.message}
                </p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Exclusions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="exclude_paths">Exclude Paths</Label>
              <Input
                id="exclude_paths"
                placeholder="/tmp,/var/log,*.bak"
                {...form.register('exclude_paths')}
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                Comma-separated list of paths or patterns to skip during scanning
              </p>
            </div>
            <div>
              <Label htmlFor="exclude_file_types">Exclude File Types</Label>
              <Input
                id="exclude_file_types"
                placeholder=".tmp,.log,.bak"
                {...form.register('exclude_file_types')}
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                Comma-separated list of file extensions to skip
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-3">
          <Button type="submit" disabled={createSchedule.isPending || updateSchedule.isPending}>
            {isEdit ? 'Save Changes' : 'Create Schedule'}
          </Button>
          <Button type="button" variant="outline" onClick={() => navigate('/scan-config')}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}
