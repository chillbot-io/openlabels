import { Check } from 'lucide-react';
import { cn } from '@/lib/utils.ts';
import { STEP_LABELS, type WizardStep } from '../types.ts';

export function StepIndicator({ steps, currentStep }: { steps: WizardStep[]; currentStep: WizardStep }) {
  const currentIdx = steps.indexOf(currentStep);
  return (
    <div className="flex items-center justify-center gap-1.5 flex-wrap">
      {steps.map((step, i) => (
        <div key={step} className="flex items-center gap-1.5">
          <div
            className={cn(
              'flex h-7 w-7 items-center justify-center rounded-full text-xs font-medium',
              i < currentIdx ? 'bg-green-500 text-white' :
              i === currentIdx ? 'bg-blue-600 text-white' :
              'bg-gray-200 text-gray-500',
            )}
          >
            {i < currentIdx ? <Check className="h-3.5 w-3.5" /> : i + 1}
          </div>
          <span className={cn(
            'text-xs hidden sm:inline',
            i === currentIdx ? 'font-medium' : 'text-gray-400',
          )}>
            {STEP_LABELS[step]}
          </span>
          {i < steps.length - 1 && <div className="h-px w-6 bg-gray-300" />}
        </div>
      ))}
    </div>
  );
}
