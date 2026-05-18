import React from 'react'
import { cx } from './glass'

function GlassNavbar({ className = '', children }) {
  return (
    <nav
      className={cx(
        'sticky top-0 z-50 bg-transparent shadow-none',
        className
      )}
    >
      <div className="relative z-10">
        {children}
      </div>
    </nav>
  )
}

export default GlassNavbar
