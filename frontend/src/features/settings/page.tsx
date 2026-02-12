import { useSettings, useUpdateSettings } from '@/api/hooks/use-settings.ts';
import { useUsers } from '@/api/hooks/use-users.ts';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useAuthStore } from '@/stores/auth-store.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Setting } from '@/api/types.ts';

function SettingsTab({ category }: { category: string }) {
  const settings = useSettings();
  const updateSettings = useUpdateSettings();
  const addToast = useUIStore((s) => s.addToast);

  const filtered = (settings.data ?? []).filter((s: Setting) => s.category === category);

  if (settings.isLoading) return <Skeleton className="h-48" />;

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        {filtered.length === 0 ? (
          <p className="text-sm text-[var(--muted-foreground)]">No settings in this category</p>
        ) : (
          filtered.map((setting: Setting) => (
            <div key={setting.key} className="space-y-1">
              <Label htmlFor={`setting-${setting.key}`}>{setting.key}</Label>
              <p className="text-xs text-[var(--muted-foreground)]" id={`setting-desc-${setting.key}`}>{setting.description}</p>
              <div className="flex gap-2">
                <Input
                  id={`setting-${setting.key}`}
                  aria-describedby={`setting-desc-${setting.key}`}
                  defaultValue={String(setting.value ?? '')}
                  onBlur={(e) => {
                    if (e.target.value !== String(setting.value ?? '')) {
                      updateSettings.mutate(
                        { category, settings: { [setting.key]: e.target.value } },
                        {
                          onSuccess: () => addToast({ level: 'success', message: `${setting.key} updated` }),
                          onError: (err) => addToast({ level: 'error', message: err.message }),
                        },
                      );
                    }
                  }}
                />
              </div>
            </div>
          ))
        )}
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

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      {!isAdmin ? (
        <p className="text-[var(--muted-foreground)]" role="alert">Settings are only accessible to administrators.</p>
      ) : (
        <Tabs defaultValue="general">
          <TabsList aria-label="Settings categories">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="azure">Azure AD</TabsTrigger>
            <TabsTrigger value="detection">Detection</TabsTrigger>
            <TabsTrigger value="entities">Entities</TabsTrigger>
            <TabsTrigger value="adapters">Adapters</TabsTrigger>
            <TabsTrigger value="users">Users</TabsTrigger>
          </TabsList>

          <TabsContent value="general"><SettingsTab category="general" /></TabsContent>
          <TabsContent value="azure"><SettingsTab category="azure" /></TabsContent>
          <TabsContent value="detection"><SettingsTab category="detection" /></TabsContent>
          <TabsContent value="entities"><SettingsTab category="entities" /></TabsContent>
          <TabsContent value="adapters"><SettingsTab category="adapters" /></TabsContent>
          <TabsContent value="users"><UsersTab /></TabsContent>
        </Tabs>
      )}
    </div>
  );
}
