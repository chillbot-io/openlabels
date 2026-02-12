import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { settingsApi } from '@/api/endpoints/settings.ts';
import { usersApi } from '@/api/endpoints/users.ts';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useAuthStore } from '@/stores/auth-store.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Setting, User, PaginatedResponse } from '@/api/types.ts';

function SettingsTab({ category }: { category: string }) {
  const settings = useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.list(),
    staleTime: 10 * 60_000,
  });

  const queryClient = useQueryClient();
  const updateSetting = useMutation({
    mutationFn: ({ key, value }: { key: string; value: unknown }) => settingsApi.update(key, value),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings'] }),
  });
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
              <Label>{setting.key}</Label>
              <p className="text-xs text-[var(--muted-foreground)]">{setting.description}</p>
              <div className="flex gap-2">
                <Input
                  defaultValue={String(setting.value ?? '')}
                  onBlur={(e) => {
                    if (e.target.value !== String(setting.value ?? '')) {
                      updateSetting.mutate(
                        { key: setting.key, value: e.target.value },
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
  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list(),
  });

  if (users.isLoading) return <Skeleton className="h-48" />;

  return (
    <Card>
      <CardContent className="p-0">
        <div className="divide-y">
          {((users.data as PaginatedResponse<User>)?.items ?? []).map((user: User) => (
            <div key={user.id} className="flex items-center justify-between px-4 py-3">
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
        <p className="text-[var(--muted-foreground)]">Settings are only accessible to administrators.</p>
      ) : (
        <Tabs defaultValue="general">
          <TabsList>
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
