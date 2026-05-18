import React from 'react'
import { cx, glassPanelClass } from './glass'

function GlassCard({
  as: Tag = 'div',
  theme = 'dark',
  className = '',
  contentClassName = 'p-6',
  interactive = false,
  elevated = false,
  children,
  ...props
}) {
  return React.createElement(
    Tag,
    {
      className: cx(glassPanelClass(theme, { interactive, elevated }), className),
      ...props,
    },
    <div className={cx('relative z-10', contentClassName)}>
      {children}
    </div>
  )
}

export default GlassCard
