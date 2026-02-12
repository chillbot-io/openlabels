import { cn } from '@/lib/utils.ts';
import { RISK_COLORS, type RiskTier } from '@/lib/constants.ts';

interface RiskBadgeProps {
  tier: RiskTier;
  className?: string;
}

export function RiskBadge({ tier, className }: RiskBadgeProps) {
  const colors = RISK_COLORS[tier];
  return (
    <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold', colors.bg, colors.text, className)}>
      {tier}
    </span>
  );
}
