import React from 'react'
import { cx, glassButtonClass } from './glass'

function GlassButton({
  theme = 'dark',
  variant = 'neutral',
  active = false,
  size = 'md',
  block = false,
  className = '',
  type = 'button',
  children,
  ...props
}) {
  return (
    <button
      type={type}
      className={cx(glassButtonClass(theme, { variant, active, size, block }), className)}
      {...props}
    >
      <span className="relative z-10 inline-flex items-center gap-2">
        {children}
      </span>
    </button>
  )
}

export default GlassButton
