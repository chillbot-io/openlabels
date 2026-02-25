import { useState } from 'react';
import { ArrowRight, ArrowLeft, Loader2, Server, Eye, EyeOff } from 'lucide-react';
import { enumerateApi } from '@/api/endpoints/enumerate.ts';
import { credentialsApi } from '@/api/endpoints/credentials.ts';
import type { EnumeratedResource } from '@/api/endpoints/enumerate.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { cn } from '@/lib/utils.ts';
import type { SmbConfig } from '../types.ts';

export function SmbSetupStep({
  config,
  onChange,
  onDone,
  onBack,
}: {
  config: SmbConfig;
  onChange: (config: SmbConfig) => void;
  onDone: () => void;
  onBack: () => void;
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validated, setValidated] = useState(false);
  const [shares, setShares] = useState<EnumeratedResource[]>([]);
  const [selectedShares, setSelectedShares] = useState<Set<string>>(new Set());
  const [error, setError] = useState('');

  const handleValidate = async () => {
    setValidating(true);
    setError('');
    try {
      const creds = {
        host: config.host,
        username: config.username,
        password: config.password,
      };
      const resp = await enumerateApi.enumerate({
        source_type: 'smb',
        credentials: creds,
      });
      setShares(resp.resources);
      setValidated(true);
      // Auto-select all shares
      setSelectedShares(new Set(resp.resources.map(r => r.id)));
      if (resp.resources.length === 0) {
        setError('Connected successfully but no shares were found.');
      }

      // Persist credentials if "save password" is checked
      if (config.savePassword) {
        await credentialsApi.save({
          source_type: 'smb',
          name: `SMB — ${config.host}`,
          credentials: creds,
        }).catch(() => {
          // Non-fatal: credentials will still work inline for this session
        });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Connection failed');
    } finally {
      setValidating(false);
    }
  };

  const toggleShare = (id: string) => {
    setSelectedShares(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleDone = () => {
    const selected = shares.filter(s => selectedShares.has(s.id));
    onChange({ ...config, selectedShares: selected });
    onDone();
  };

  const canValidate = config.host.trim().length > 0;

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Setup SMB File Share</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Enter the server details and credentials to connect.
          </p>
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-sm font-medium" htmlFor="smb-host">Server / Host</label>
            <Input
              id="smb-host"
              placeholder="fileserver.contoso.com or 10.0.0.5"
              value={config.host}
              onChange={e => onChange({ ...config, host: e.target.value })}
            />
          </div>
          <div>
            <label className="text-sm font-medium" htmlFor="smb-user">Service Account</label>
            <Input
              id="smb-user"
              placeholder="DOMAIN\svc-openlabels or user@domain"
              value={config.username}
              onChange={e => onChange({ ...config, username: e.target.value })}
            />
          </div>
          <div>
            <label className="text-sm font-medium" htmlFor="smb-pass">Password</label>
            <div className="relative">
              <Input
                id="smb-pass"
                type={showPassword ? 'text' : 'password'}
                value={config.password}
                onChange={e => onChange({ ...config, password: e.target.value })}
              />
              <button
                type="button"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                onClick={() => setShowPassword(p => !p)}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              className="rounded"
              checked={config.savePassword}
              onChange={e => onChange({ ...config, savePassword: e.target.checked })}
            />
            <span className="text-sm">Save password securely</span>
          </label>
        </div>

        <Button
          onClick={handleValidate}
          disabled={!canValidate || validating}
          variant="outline"
        >
          {validating ? (
            <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Validating...</>
          ) : (
            <><Server className="mr-2 h-4 w-4" /> Validate &amp; Browse Shares</>
          )}
        </Button>

        {error && (
          <p className="text-sm text-red-600">{error}</p>
        )}

        {validated && shares.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">
                Select shares ({selectedShares.size} of {shares.length})
              </p>
              <Button
                type="button" variant="outline" size="sm"
                onClick={() => {
                  if (selectedShares.size === shares.length) {
                    setSelectedShares(new Set());
                  } else {
                    setSelectedShares(new Set(shares.map(s => s.id)));
                  }
                }}
              >
                {selectedShares.size === shares.length ? 'Deselect All' : 'Select All'}
              </Button>
            </div>
            <div className="max-h-48 space-y-1 overflow-y-auto rounded-md border p-2">
              {shares.map(share => (
                <label
                  key={share.id}
                  className={cn(
                    'flex cursor-pointer items-start gap-3 rounded-md px-3 py-2 transition-colors hover:bg-[var(--muted)]',
                    selectedShares.has(share.id) && 'bg-[var(--accent)]',
                  )}
                >
                  <input
                    type="checkbox"
                    className="mt-0.5 rounded"
                    checked={selectedShares.has(share.id)}
                    onChange={() => toggleShare(share.id)}
                  />
                  <div className="min-w-0 flex-1">
                    <span className="text-sm font-medium">{share.name}</span>
                    <p className="truncate text-xs text-[var(--muted-foreground)]">{share.description || share.path}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button
            onClick={handleDone}
            disabled={!validated || selectedShares.size === 0}
          >
            Next <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
