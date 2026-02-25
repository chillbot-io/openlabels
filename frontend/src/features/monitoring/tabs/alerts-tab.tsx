import { useState } from 'react';
import { useSystemAlerts, useCreateSystemAlert, useDeleteSystemAlert } from '@/api/hooks/use-monitoring.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';

export function AlertsTab() {
  const alerts = useSystemAlerts();
  const createAlert = useCreateSystemAlert();
  const deleteAlert = useDeleteSystemAlert();
  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formComponent, setFormComponent] = useState('db');
  const [formCondition, setFormCondition] = useState('unhealthy');
  const [formThreshold, setFormThreshold] = useState('');

  const handleCreate = () => {
    createAlert.mutate({
      name: formName,
      component: formComponent,
      condition: formCondition,
      threshold: formThreshold ? parseFloat(formThreshold) : undefined,
      actions: ['log', 'notify'],
    }, {
      onSuccess: () => {
        setShowForm(false);
        setFormName('');
        setFormThreshold('');
      },
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--muted-foreground)]">
          Configure alerts for system component failures and resource thresholds.
        </p>
        <Button size="sm" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : 'Add Alert'}
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="space-y-3 p-4">
            <div className="grid grid-cols-4 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium">Name</label>
                <Input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Alert name" />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Component</label>
                <select
                  className="h-9 w-full rounded-md border border-[var(--border)] bg-transparent px-3 text-sm"
                  value={formComponent}
                  onChange={(e) => setFormComponent(e.target.value)}
                >
                  {['api', 'db', 'queue', 'redis', 'worker', 'task', 'disk', 'memory', 'cpu'].map((c) => (
                    <option key={c} value={c}>{c.toUpperCase()}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Condition</label>
                <select
                  className="h-9 w-full rounded-md border border-[var(--border)] bg-transparent px-3 text-sm"
                  value={formCondition}
                  onChange={(e) => setFormCondition(e.target.value)}
                >
                  <option value="unhealthy">Unhealthy</option>
                  <option value="threshold_exceeded">Threshold Exceeded</option>
                  <option value="offline">Offline</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Threshold (%)</label>
                <div className="flex gap-2">
                  <Input
                    type="number"
                    value={formThreshold}
                    onChange={(e) => setFormThreshold(e.target.value)}
                    placeholder="e.g. 90"
                    disabled={formCondition !== 'threshold_exceeded'}
                  />
                  <Button size="sm" onClick={handleCreate} disabled={!formName || createAlert.isPending}>
                    {createAlert.isPending ? 'Creating...' : 'Create'}
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          {alerts.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : alerts.data && alerts.data.length > 0 ? (
            <div className="divide-y" role="list" aria-label="System alert rules">
              {alerts.data.map((alert) => (
                <div key={alert.id} className="flex items-center justify-between px-4 py-3" role="listitem">
                  <div className="flex items-center gap-3">
                    <Badge variant={alert.enabled ? 'default' : 'secondary'}>
                      {alert.enabled ? 'Active' : 'Disabled'}
                    </Badge>
                    <div>
                      <p className="text-sm font-medium">{alert.name}</p>
                      <p className="text-xs text-[var(--muted-foreground)]">
                        {alert.component.toUpperCase()} &middot; {alert.condition}
                        {alert.threshold != null ? ` > ${alert.threshold}%` : ''}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[var(--muted-foreground)]">
                      {alert.actions.join(', ')}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => deleteAlert.mutate(alert.id)}
                      disabled={deleteAlert.isPending}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-[var(--muted-foreground)]">
              No alert rules configured. Click "Add Alert" to create one.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
