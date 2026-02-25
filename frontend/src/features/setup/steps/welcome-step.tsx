import { ArrowRight } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { LogoIcon } from '@/components/brand/logo.tsx';

export function WelcomeStep({ onNext }: { onNext: () => void }) {
  return (
    <Card>
      <CardContent className="space-y-6 p-8 text-center">
        <LogoIcon className="mx-auto h-16 w-auto" />
        <div>
          <h1 className="text-3xl font-bold">Welcome to OpenLabels</h1>
          <p className="mt-2 text-[var(--muted-foreground)]">
            Sensitive data discovery and protection for your files.
            Let's connect your data sources.
          </p>
        </div>
        <Button size="lg" onClick={onNext}>
          Get Started <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </CardContent>
    </Card>
  );
}
