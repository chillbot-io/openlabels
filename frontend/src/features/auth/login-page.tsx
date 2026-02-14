import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent, CardHeader, CardDescription } from '@/components/ui/card.tsx';
import { LogoIcon } from '@/components/brand/logo.tsx';

export function Component() {
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
        <CardContent className="space-y-4">
          <Button
            className="w-full"
            onClick={() => {
              window.location.href = '/api/v1/auth/login';
            }}
          >
            Sign in with Microsoft
          </Button>
          <p className="text-center text-xs text-[var(--muted-foreground)]">
            Authenticates via your organization's Azure AD
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
