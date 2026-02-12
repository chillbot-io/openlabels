import { Link } from 'react-router';
import { FileQuestion } from 'lucide-react';
import { Button } from '@/components/ui/button.tsx';

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <FileQuestion className="mb-4 h-16 w-16 text-[var(--muted-foreground)]" />
      <h1 className="text-2xl font-bold">Page not found</h1>
      <p className="mt-2 text-[var(--muted-foreground)]">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <Button className="mt-6" asChild>
        <Link to="/dashboard">Go to Dashboard</Link>
      </Button>
    </div>
  );
}
