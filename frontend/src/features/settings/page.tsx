import { useState, useMemo } from 'react';
import { useSettings, useUpdateSettings } from '@/api/hooks/use-settings.ts';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useAuthStore } from '@/stores/auth-store.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { AllSettings } from '@/api/types.ts';

type SettingsCategory = 'scan' | 'entities' | 'fanout';

function toFormValues(data: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(data)) {
    result[key] = Array.isArray(value) ? value.join(', ') : String(value ?? '');
  }
  return result;
}

function SettingsTab({ category, settings }: { category: SettingsCategory; settings: AllSettings }) {
  const updateSettings = useUpdateSettings();
  const addToast = useUIStore((s) => s.addToast);
  const categoryData = settings[category];
  const [formValues, setFormValues] = useState(() => toFormValues(categoryData));

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

function AzureSettingsTab({ settings }: { settings: AllSettings }) {
  const updateSettings = useUpdateSettings();
  const addToast = useUIStore((s) => s.addToast);
  const azure = settings.azure;

  const [tenantId, setTenantId] = useState(azure.azure_tenant_id ?? '');
  const [clientId, setClientId] = useState(azure.azure_client_id ?? '');
  const [clientSecret, setClientSecret] = useState('');

  const handleSave = () => {
    const payload: Record<string, unknown> = {
      azure_tenant_id: tenantId,
      azure_client_id: clientId,
    };
    if (clientSecret) {
      payload.azure_client_secret = clientSecret;
    }
    updateSettings.mutate(
      { category: 'azure', settings: payload },
      {
        onSuccess: () => {
          addToast({ level: 'success', message: 'Azure AD settings updated' });
          setClientSecret('');
        },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        <div className="space-y-1">
          <Label htmlFor="azure-tenant-id">Tenant ID</Label>
          <Input
            id="azure-tenant-id"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="azure-client-id">Client ID</Label>
          <Input
            id="azure-client-id"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          />
        </div>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Label htmlFor="azure-client-secret">Client Secret</Label>
            {azure.azure_client_secret_set ? (
              <Badge variant="secondary" className="text-[10px]">configured</Badge>
            ) : (
              <Badge variant="outline" className="text-[10px] text-[var(--muted-foreground)]">not set</Badge>
            )}
          </div>
          <Input
            id="azure-client-secret"
            type="password"
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            placeholder={azure.azure_client_secret_set ? 'Leave blank to keep current secret' : 'Enter client secret'}
          />
        </div>
        <Button onClick={handleSave} disabled={updateSettings.isPending}>
          {updateSettings.isPending ? 'Saving...' : 'Save'}
        </Button>
      </CardContent>
    </Card>
  );
}

export function Component() {
  const user = useAuthStore((s) => s.user);
  // UX guard only — the backend API endpoints independently verify admin role
  // on every request. This check prevents non-admins from seeing the settings
  // UI, but does not serve as a security boundary.
  const isAdmin = user?.role === 'admin';
  const settings = useSettings();

  // Stable key that changes when server data changes, causing React to
  // remount the tab components and re-initialize their form state.
  const dataKey = useMemo(
    () => (settings.data ? JSON.stringify(settings.data) : ''),
    [settings.data],
  );

  if (!isAdmin) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="mt-4 text-[var(--muted-foreground)]" role="alert">Settings are only accessible to administrators.</p>
      </div>
    );
  }

  if (settings.isLoading) return <Skeleton className="m-6 h-48" />;
  if (settings.error) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="mt-4 text-red-600" role="alert">Failed to load settings: {settings.error.message}</p>
      </div>
    );
  }
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
        </TabsList>

        <TabsContent value="azure">
          <AzureSettingsTab key={dataKey} settings={settings.data} />
        </TabsContent>
        <TabsContent value="scan">
          <SettingsTab key={`scan-${dataKey}`} category="scan" settings={settings.data} />
        </TabsContent>
        <TabsContent value="entities">
          <SettingsTab key={`entities-${dataKey}`} category="entities" settings={settings.data} />
        </TabsContent>
        <TabsContent value="fanout">
          <SettingsTab key={`fanout-${dataKey}`} category="fanout" settings={settings.data} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
