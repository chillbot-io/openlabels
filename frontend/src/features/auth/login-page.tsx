import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent, CardHeader, CardDescription } from '@/components/ui/card.tsx';
import { LogoIcon } from '@/components/brand/logo.tsx';

interface AuthProviderInfo {
  key: string;
  provider_type: string;
  display_name: string;
  button_style: string;
  login_url: string;
}

interface AuthConfig {
  providers: AuthProviderInfo[];
}

function ProviderIcon({ style }: { style: string }) {
  if (style === 'microsoft') {
    return (
      <svg className="mr-2 h-5 w-5" viewBox="0 0 21 21" fill="none">
        <rect x="1" y="1" width="9" height="9" fill="#F25022" />
        <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
        <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
        <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
      </svg>
    );
  }
  if (style === 'google') {
    return (
      <svg className="mr-2 h-5 w-5" viewBox="0 0 24 24">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4" />
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
      </svg>
    );
  }
  if (style === 'github') {
    return (
      <svg className="mr-2 h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
      </svg>
    );
  }
  // Generic lock icon for other providers
  return (
    <svg className="mr-2 h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );
}

export function Component() {
  const [providers, setProviders] = useState<AuthProviderInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/v1/auth/config')
      .then((res) => res.json())
      .then((config: AuthConfig) => {
        setProviders(config.providers ?? []);
        setLoading(false);
      })
      .catch(() => {
        setProviders([{
          key: 'azure_ad',
          provider_type: 'azure_ad',
          display_name: 'Microsoft',
          button_style: 'microsoft',
          login_url: '/api/v1/auth/login',
        }]);
        setLoading(false);
      });
  }, []);

  const handleLogin = (loginUrl: string) => {
    window.location.href = loginUrl;
  };

  const isDev = providers.length === 1 && providers[0]?.provider_type === 'none';

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4">
      <Card className="w-full max-w-md" role="main">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2">
            <LogoIcon className="mx-auto h-12 w-auto" />
          </div>
          <h1 className="text-2xl font-semibold leading-none tracking-tight">openlabels</h1>
          <CardDescription>
            Sensitive data discovery and protection platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {loading ? (
            <Button className="w-full" disabled>Loading...</Button>
          ) : (
            providers.map((p) => (
              <Button
                key={p.key}
                variant={providers.length > 1 ? 'outline' : 'default'}
                className="w-full"
                onClick={() => handleLogin(p.login_url)}
              >
                <ProviderIcon style={p.button_style} />
                Sign in with {p.display_name}
              </Button>
            ))
          )}
          <p className="text-center text-xs text-[var(--muted-foreground)]">
            {isDev
              ? 'Development mode — no authentication required'
              : providers.length === 1
                ? `Authenticates via ${providers[0]?.display_name}`
                : 'Choose your identity provider to sign in'}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
