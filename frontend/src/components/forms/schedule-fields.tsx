import type { UseFormReturn } from 'react-hook-form';
import { z } from 'zod';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { describeCron } from '@/lib/date.ts';

/**
 * Shared Zod schema for the schedule fields common to both scan-config
 * and schedules forms. Individual pages can extend this with additional fields.
 */
export const scheduleFieldsSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  cron: z.string().min(1, 'Cron expression is required').regex(
    /^(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)\s+(\*|[0-9,\-\/]+)$/,
    'Invalid cron expression (expected 5 fields: min hour day month weekday)',
  ),
  target_id: z.string().min(1, 'Select a target'),
  enabled: z.boolean(),
});

export type ScheduleFieldsData = z.infer<typeof scheduleFieldsSchema>;

interface ScheduleFieldsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  form: UseFormReturn<any>;
  /** Label for the name field, defaults to "Name" */
  nameLabel?: string;
  /** Label for the target section, defaults to "Target" */
  targetLabel?: string;
}

/**
 * Shared form fields used by both the scan-config/form-page and
 * schedules/form-page. Renders name, enabled toggle, target selector,
 * and cron expression fields.
 */
export function ScheduleFields({
  form,
  nameLabel = 'Name',
  targetLabel = 'Target',
}: ScheduleFieldsProps) {
  const targets = useTargets();
  const cronValue = form.watch('cron');
  const cronDescription = describeCron(cronValue);

  return (
    <>
      <Card>
        <CardHeader><CardTitle>Details</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="name">{nameLabel}</Label>
            <Input
              id="name"
              aria-describedby={form.formState.errors.name ? 'name-error' : undefined}
              aria-invalid={!!form.formState.errors.name}
              {...form.register('name')}
            />
            {form.formState.errors.name && (
              <p id="name-error" role="alert" className="mt-1 text-xs text-red-500">
                {form.formState.errors.name.message as string}
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
        <CardHeader><CardTitle>{targetLabel}</CardTitle></CardHeader>
        <CardContent>
          <Label htmlFor="target_id">{targetLabel}</Label>
          <Select
            value={form.watch('target_id')}
            onValueChange={(v) => form.setValue('target_id', v, { shouldValidate: true })}
          >
            <SelectTrigger id="target_id" aria-invalid={!!form.formState.errors.target_id}>
              <SelectValue placeholder="Select a target" />
            </SelectTrigger>
            <SelectContent>
              {(targets.data?.items ?? []).map((target) => (
                <SelectItem key={target.id} value={target.id}>{target.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {form.formState.errors.target_id && (
            <p role="alert" className="mt-1 text-xs text-red-500">
              {form.formState.errors.target_id.message as string}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Frequency and Timing</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="cron">Cron Expression</Label>
            <Input
              id="cron"
              aria-describedby={`cron-description${form.formState.errors.cron ? ' cron-error' : ''}`}
              aria-invalid={!!form.formState.errors.cron}
              {...form.register('cron')}
              placeholder="0 2 * * 1"
            />
            <p id="cron-description" className="mt-1 text-xs text-[var(--muted-foreground)]">
              {cronDescription.join(' | ')}
            </p>
            {form.formState.errors.cron && (
              <p id="cron-error" role="alert" className="mt-1 text-xs text-red-500">
                {form.formState.errors.cron.message as string}
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </>
  );
}
