import { cn } from '@/lib/utils.ts';

/**
 * The OpenLabels tag icon — renders the /logo-icon.svg from public/.
 * Use variant="white" on dark backgrounds.
 */
export function LogoIcon({ className, variant = 'default' }: { className?: string; variant?: 'default' | 'white' }) {
  return (
    <img
      src={variant === 'white' ? '/logo-icon-white.svg' : '/logo-icon.svg'}
      alt=""
      aria-hidden="true"
      className={cn('h-6 w-auto', className)}
    />
  );
}

/**
 * Full logo: "openlabels" wordmark + tag icon.
 * Renders /logo.svg (full) or /logo-icon.svg (icon-only) from public/.
 * Use variant="white" on dark backgrounds.
 */
export function Logo({ className, iconOnly, variant = 'default' }: { className?: string; iconOnly?: boolean; variant?: 'default' | 'white' }) {
  return iconOnly ? (
    <LogoIcon className={className} variant={variant} />
  ) : (
    <img
      src={variant === 'white' ? '/logo-white.svg' : '/logo.svg'}
      alt="OpenLabels"
      className={cn('h-8 w-auto', className)}
    />
  );
}
