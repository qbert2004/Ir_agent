export function cx(...classes) {
  return classes.filter(Boolean).join(' ')
}

export function glassPanelClass(theme = 'dark', options = {}) {
  const { interactive = false, elevated = false } = options
  const isDark = theme === 'dark'

  return cx(
    'group relative isolate overflow-hidden rounded-[28px] border backdrop-blur-[28px] transition-all duration-300',
    'before:pointer-events-none before:absolute before:inset-0 before:bg-[linear-gradient(135deg,rgba(255,255,255,0.18),rgba(255,255,255,0.04)_26%,transparent_52%),radial-gradient(circle_at_top_left,rgba(56,189,248,0.16),transparent_34%),radial-gradient(circle_at_bottom_right,rgba(129,140,248,0.14),transparent_30%)]',
    'after:pointer-events-none after:absolute after:inset-x-6 after:top-0 after:h-px after:bg-gradient-to-r after:from-transparent after:via-white/65 after:to-transparent',
    isDark
      ? 'border-white/12 bg-white/[0.08] shadow-[0_24px_80px_rgba(2,8,23,0.42),0_0_32px_rgba(59,130,246,0.10),inset_0_1px_0_rgba(255,255,255,0.16),inset_0_-1px_0_rgba(255,255,255,0.04)]'
      : 'border-white/36 bg-white/[0.24] shadow-[0_24px_70px_rgba(15,23,42,0.08),0_0_28px_rgba(56,189,248,0.06),inset_0_1px_0_rgba(255,255,255,0.62),inset_0_-1px_0_rgba(255,255,255,0.12)]',
    elevated && (isDark
      ? 'bg-white/[0.10] shadow-[0_32px_96px_rgba(2,8,23,0.52),0_0_48px_rgba(56,189,248,0.12),inset_0_1px_0_rgba(255,255,255,0.18)]'
      : 'bg-white/[0.30] shadow-[0_32px_96px_rgba(15,23,42,0.10),0_0_34px_rgba(56,189,248,0.08),inset_0_1px_0_rgba(255,255,255,0.70),inset_0_-1px_0_rgba(255,255,255,0.14)]'),
    interactive && (isDark
      ? 'hover:scale-[1.01] hover:bg-white/[0.11] hover:brightness-110 hover:shadow-[0_28px_86px_rgba(2,8,23,0.5),0_0_52px_rgba(56,189,248,0.14),inset_0_1px_0_rgba(255,255,255,0.20)]'
      : 'hover:scale-[1.01] hover:bg-white/[0.30] hover:brightness-105 hover:shadow-[0_26px_86px_rgba(15,23,42,0.12),0_0_38px_rgba(56,189,248,0.10),inset_0_1px_0_rgba(255,255,255,0.74),inset_0_-1px_0_rgba(255,255,255,0.16)]')
  )
}

export function glassButtonClass(theme = 'dark', options = {}) {
  const {
    variant = 'neutral',
    active = false,
    size = 'md',
    block = false,
  } = options
  const isDark = theme === 'dark'

  const sizeMap = {
    xs: 'px-3 py-1.5 text-[11px]',
    sm: 'px-3.5 py-2 text-sm',
    md: 'px-4 py-2.5 text-sm',
    lg: 'px-5 py-3 text-sm',
    icon: 'h-11 w-11',
  }

  const variants = {
    neutral: isDark
      ? 'border-white/12 bg-white/[0.08] text-white/88 hover:bg-white/[0.12] hover:text-white'
      : 'border-white/34 bg-white/[0.24] text-slate-900/88 hover:bg-white/[0.32] hover:text-slate-950',
    accent: isDark
      ? 'border-cyan-300/22 bg-cyan-300/[0.14] text-cyan-50 shadow-[0_0_24px_rgba(56,189,248,0.14)] hover:bg-cyan-300/[0.20] hover:shadow-[0_0_34px_rgba(56,189,248,0.18)]'
      : 'border-cyan-200/70 bg-cyan-100/42 text-cyan-950 shadow-[0_0_16px_rgba(56,189,248,0.08)] hover:bg-cyan-50/56',
    tab: active
      ? isDark
        ? 'border-cyan-300/24 bg-cyan-300/[0.16] text-cyan-50 shadow-[0_0_26px_rgba(56,189,248,0.14)]'
        : 'border-cyan-200/76 bg-white/[0.28] text-cyan-950 shadow-[0_0_14px_rgba(56,189,248,0.06)]'
      : isDark
        ? 'border-transparent bg-transparent text-white/58 hover:border-white/10 hover:bg-white/[0.08] hover:text-white/90'
        : 'border-transparent bg-transparent text-slate-600 hover:border-white/36 hover:bg-white/[0.18] hover:text-slate-950',
    ghost: isDark
      ? 'border-transparent bg-transparent text-white/76 hover:border-white/10 hover:bg-white/[0.08] hover:text-white'
      : 'border-transparent bg-transparent text-slate-700/80 hover:border-white/36 hover:bg-white/[0.18] hover:text-slate-950',
    success: isDark
      ? 'border-emerald-300/20 bg-emerald-400/[0.14] text-emerald-50 shadow-[0_0_24px_rgba(16,185,129,0.14)] hover:bg-emerald-400/[0.20]'
      : 'border-emerald-200/70 bg-emerald-100/42 text-emerald-950 hover:bg-emerald-50/58',
    danger: isDark
      ? 'border-rose-300/20 bg-rose-400/[0.14] text-rose-50 shadow-[0_0_24px_rgba(244,63,94,0.14)] hover:bg-rose-400/[0.20]'
      : 'border-rose-200/70 bg-rose-100/42 text-rose-950 hover:bg-rose-50/58',
  }

  return cx(
    'relative inline-flex items-center justify-center gap-2 rounded-2xl border font-medium backdrop-blur-xl transition-all duration-300',
    'shadow-[inset_0_1px_0_rgba(255,255,255,0.18)] hover:scale-[1.02] hover:brightness-110 active:scale-[0.99]',
    'disabled:pointer-events-none disabled:opacity-50',
    block && 'w-full',
    sizeMap[size] || sizeMap.md,
    variants[variant] || variants.neutral,
  )
}

export function glassInputClass(theme = 'dark') {
  const isDark = theme === 'dark'
  return cx(
    'w-full rounded-2xl border px-4 py-3 text-sm outline-none backdrop-blur-xl transition-all duration-300',
    'shadow-[inset_0_1px_0_rgba(255,255,255,0.14)]',
    isDark
      ? 'border-white/12 bg-white/[0.08] text-white placeholder:text-white/38 focus:border-cyan-300/30 focus:bg-white/[0.12] focus:shadow-[0_0_24px_rgba(56,189,248,0.10),inset_0_1px_0_rgba(255,255,255,0.18)]'
      : 'border-white/34 bg-white/[0.24] text-slate-900 placeholder:text-slate-500 focus:border-cyan-300/44 focus:bg-white/[0.30] focus:shadow-[0_0_18px_rgba(56,189,248,0.08),inset_0_1px_0_rgba(255,255,255,0.68)]'
  )
}

export function glassSurfaceClass(theme = 'dark', options = {}) {
  const { compact = false } = options
  const isDark = theme === 'dark'
  return cx(
    'rounded-2xl border backdrop-blur-xl',
    compact ? 'px-3 py-2' : 'p-3',
    isDark
      ? 'border-white/10 bg-white/[0.06] shadow-[inset_0_1px_0_rgba(255,255,255,0.10)]'
      : 'border-white/34 bg-white/[0.22] shadow-[inset_0_1px_0_rgba(255,255,255,0.62)]'
  )
}

export function glassMutedTextClass(theme = 'dark') {
  return theme === 'dark' ? 'text-white/62' : 'text-slate-700/70'
}
