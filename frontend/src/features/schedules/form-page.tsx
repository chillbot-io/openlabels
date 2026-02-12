import { useNavigate, useParams } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useSchedule, useCreateSchedule, useUpdateSchedule } from '@/api/hooks/use-schedules.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { describeCron } from '@/lib/date.ts';
import { useUIStore } from '@/stores/ui-store.ts';

const scheduleSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  cron_expression: z.string().min(1, 'Cron expression is required'),
  target_ids: z.array(z.string()).min(1, 'Select at least one target'),
  enabled: z.boolean(),
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
    defaultValues: { name: '', cron_expression: '0 2 * * 1', target_ids: [], enabled: true },
    values: schedule.data ? {
      name: schedule.data.name,
      cron_expression: schedule.data.cron_expression,
      target_ids: schedule.data.target_ids,
      enabled: schedule.data.enabled,
    } : undefined,
  });

  if (isEdit && schedule.isLoading) return <LoadingSkeleton />;

  const cron = form.watch('cron_expression');
  const cronDescription = describeCron(cron);
  const selectedTargets = form.watch('target_ids');

  const onSubmit = (data: FormData) => {
    if (isEdit) {
      updateSchedule.mutate({ id: scheduleId!, ...data }, {
        onSuccess: () => { addToast({ level: 'success', message: 'Schedule updated' }); navigate('/schedules'); },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    } else {
      createSchedule.mutate(data, {
        onSuccess: () => { addToast({ level: 'success', message: 'Schedule created' }); navigate('/schedules'); },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      });
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold">{isEdit ? 'Edit Schedule' : 'New Schedule'}</h1>

      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader><CardTitle>Details</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input id="name" {...form.register('name')} />
              {form.formState.errors.name && (
                <p className="mt-1 text-xs text-red-500">{form.formState.errors.name.message}</p>
              )}
            </div>

            <div>
              <Label htmlFor="cron">Cron Expression</Label>
              <Input id="cron" {...form.register('cron_expression')} placeholder="0 2 * * 1" />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">{cronDescription.join(' | ')}</p>
              {form.formState.errors.cron_expression && (
                <p className="mt-1 text-xs text-red-500">{form.formState.errors.cron_expression.message}</p>
              )}
            </div>

            <label className="flex items-center gap-2">
              <input type="checkbox" {...form.register('enabled')} className="rounded" />
              <span className="text-sm">Enabled</span>
            </label>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Targets</CardTitle></CardHeader>
          <CardContent className="space-y-2 max-h-64 overflow-y-auto">
            {(targets.data?.items ?? []).map((target) => (
              <label key={target.id} className="flex items-center gap-2 rounded-md p-2 hover:bg-[var(--muted)]">
                <input
                  type="checkbox"
                  checked={selectedTargets.includes(target.id)}
                  onChange={(e) => {
                    const next = e.target.checked
                      ? [...selectedTargets, target.id]
                      : selectedTargets.filter((id) => id !== target.id);
                    form.setValue('target_ids', next, { shouldValidate: true });
                  }}
                  className="rounded"
                />
                <span className="text-sm">{target.name}</span>
              </label>
            ))}
            {form.formState.errors.target_ids && (
              <p className="text-xs text-red-500">{form.formState.errors.target_ids.message}</p>
            )}
          </CardContent>
        </Card>

        <div className="flex gap-3">
          <Button type="submit" disabled={createSchedule.isPending || updateSchedule.isPending}>
            {isEdit ? 'Save Changes' : 'Create Schedule'}
          </Button>
          <Button type="button" variant="outline" onClick={() => navigate('/schedules')}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}
