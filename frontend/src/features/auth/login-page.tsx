import { Shield } from 'lucide-react';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.tsx';

export function Component() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-primary-100">
            <Shield className="h-6 w-6 text-primary-600" />
          </div>
          <CardTitle className="text-2xl">OpenLabels</CardTitle>
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
