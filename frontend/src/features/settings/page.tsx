import { useState, useEffect } from 'react';
import { useSettings, useUpdateSettings } from '@/api/hooks/use-settings.ts';
import { useUsers } from '@/api/hooks/use-users.ts';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useAuthStore } from '@/stores/auth-store.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { AllSettings } from '@/api/types.ts';

type SettingsCategory = 'azure' | 'scan' | 'entities' | 'fanout';

function SettingsTab({ category, settings }: { category: SettingsCategory; settings: AllSettings }) {
  const updateSettings = useUpdateSettings();
  const addToast = useUIStore((s) => s.addToast);
  const categoryData = settings[category];
  const [formValues, setFormValues] = useState<Record<string, string>>({});

  useEffect(() => {
    const initial: Record<string, string> = {};
    for (const [key, value] of Object.entries(categoryData)) {
      initial[key] = Array.isArray(value) ? value.join(', ') : String(value ?? '');
    }
    setFormValues(initial);
  }, [categoryData]);

  const handleSave = () => {
    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(formValues)) {
      const original = (categoryData as Record<string, unknown>)[key];
      if (Array.isArray(original)) {
        payload[key] = value.split(',').map((v) => v.trim()).filter(Boolean);
      } else if (typeof original === 'number') {
        const n = Number(value);
        if (Number.isNaN(n)) {
          addToast({ level: 'error', message: `"${key.replace(/_/g, ' ')}" must be a number` });
          return;
        }
        payload[key] = n;
      } else if (typeof original === 'boolean') {
        payload[key] = value === 'true';
      } else {
        payload[key] = value;
      }
    }
    updateSettings.mutate(
      { category, settings: payload },
      {
        onSuccess: () => addToast({ level: 'success', message: `${category} settings updated` }),
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        {Object.entries(formValues).map(([key, value]) => {
          const original = (categoryData as Record<string, unknown>)[key];
          const isBool = typeof original === 'boolean';

          return (
            <div key={key} className="space-y-1">
              <Label htmlFor={`setting-${key}`}>{key.replace(/_/g, ' ')}</Label>
              {isBool ? (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id={`setting-${key}`}
                    checked={value === 'true'}
                    onChange={(e) => setFormValues((prev) => ({ ...prev, [key]: String(e.target.checked) }))}
                    className="rounded"
                  />
                  <span className="text-sm">{value === 'true' ? 'Enabled' : 'Disabled'}</span>
                </label>
              ) : (
                <Input
                  id={`setting-${key}`}
                  value={value}
                  onChange={(e) => setFormValues((prev) => ({ ...prev, [key]: e.target.value }))}
                />
              )}
            </div>
          );
        })}
        <Button onClick={handleSave} disabled={updateSettings.isPending}>
          {updateSettings.isPending ? 'Saving...' : 'Save'}
        </Button>
      </CardContent>
    </Card>
  );
}

function UsersTab() {
  const users = useUsers();

  if (users.isLoading) return <Skeleton className="h-48" />;

  return (
    <Card>
      <CardContent className="p-0">
        <div className="divide-y" role="list" aria-label="Users">
          {(users.data?.items ?? []).map((user) => (
            <div key={user.id} className="flex items-center justify-between px-4 py-3" role="listitem">
              <div>
                <p className="text-sm font-medium">{user.name}</p>
                <p className="text-xs text-[var(--muted-foreground)]">{user.email}</p>
              </div>
              <span className="rounded-full bg-[var(--muted)] px-2 py-0.5 text-xs font-medium">{user.role}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function Component() {
  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === 'admin';
  const settings = useSettings();

  if (!isAdmin) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="mt-4 text-[var(--muted-foreground)]" role="alert">Settings are only accessible to administrators.</p>
      </div>
    );
  }

  if (settings.isLoading) return <Skeleton className="m-6 h-48" />;
  if (!settings.data) return null;

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <Tabs defaultValue="azure">
        <TabsList aria-label="Settings categories">
          <TabsTrigger value="azure">Azure AD</TabsTrigger>
          <TabsTrigger value="scan">Scan</TabsTrigger>
          <TabsTrigger value="entities">Entities</TabsTrigger>
          <TabsTrigger value="fanout">Fanout</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
        </TabsList>

        <TabsContent value="azure"><SettingsTab category="azure" settings={settings.data} /></TabsContent>
        <TabsContent value="scan"><SettingsTab category="scan" settings={settings.data} /></TabsContent>
        <TabsContent value="entities"><SettingsTab category="entities" settings={settings.data} /></TabsContent>
        <TabsContent value="fanout"><SettingsTab category="fanout" settings={settings.data} /></TabsContent>
        <TabsContent value="users"><UsersTab /></TabsContent>
      </Tabs>
    </div>
  );
}
