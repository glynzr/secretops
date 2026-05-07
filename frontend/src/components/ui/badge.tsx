import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-border bg-secondary text-muted-foreground',
        destructive: 'border-transparent bg-destructive/20 text-destructive border-destructive/30',
        outline: 'border-border text-foreground',
        success: 'border-transparent bg-green-500/20 text-green-400 border-green-500/30',
        warning: 'border-transparent bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
        critical: 'border-transparent bg-red-500/20 text-red-400 border-red-500/30',
        high: 'border-transparent bg-orange-500/20 text-orange-400 border-orange-500/30',
        medium: 'border-transparent bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
        low: 'border-transparent bg-green-500/20 text-green-400 border-green-500/30',
        blue: 'border-transparent bg-blue-500/20 text-blue-400 border-blue-500/30',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
