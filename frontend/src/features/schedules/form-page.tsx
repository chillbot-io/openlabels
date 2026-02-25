import { useNavigate, useParams } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useSchedule, useCreateSchedule, useUpdateSchedule } from '@/api/hooks/use-schedules.ts';
import { Button } from '@/components/ui/button.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { ScheduleFields, scheduleFieldsSchema, type ScheduleFieldsData } from '@/components/forms/schedule-fields.tsx';
import { useUIStore } from '@/stores/ui-store.ts';

export function Component() {
  const { scheduleId } = useParams<{ scheduleId: string }>();
  const navigate = useNavigate();
  const isEdit = !!scheduleId;
  const schedule = useSchedule(scheduleId ?? '');
  const createSchedule = useCreateSchedule();
  const updateSchedule = useUpdateSchedule();
  const addToast = useUIStore((s) => s.addToast);

  const form = useForm<ScheduleFieldsData>({
    resolver: zodResolver(scheduleFieldsSchema),
    defaultValues: { name: '', cron: '0 2 * * 1', target_id: '', enabled: true },
    values: schedule.data ? {
      name: schedule.data.name,
      cron: schedule.data.cron ?? '',
      target_id: schedule.data.target_id,
      enabled: schedule.data.enabled,
    } : undefined,
  });

  if (isEdit && schedule.isLoading) return <LoadingSkeleton />;

  const onSubmit = (data: ScheduleFieldsData) => {
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
        <ScheduleFields form={form} />

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
