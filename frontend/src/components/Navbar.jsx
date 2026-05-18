import React, { useMemo, useState } from 'react'
import { ChevronRight, Filter, Moon, Settings, LogOut } from 'lucide-react'
import FilterPanel from './FilterPanel'

function Navbar({
  theme,
  toggleTheme,
  onLogout,
  user,
  filters,
  setFilters,
}) {
  const [showProfile, setShowProfile] = useState(false)
  const [showFilters, setShowFilters] = useState(false)
  const isDark = theme === 'dark'

  const activeFilterCount = useMemo(
    () => Object.values(filters || {}).filter((value) => value !== '').length,
    [filters],
  )

  return (
    <header className="h-16 flex items-center justify-between px-8 bg-white dark:bg-[#09090B] border-b border-slate-200/60 dark:border-[#1F1F1F] z-40 shrink-0 transition-colors">
      <div className="flex items-center gap-3">
        <span className="text-[10px] font-black uppercase text-slate-500 dark:text-zinc-500 tracking-[0.2em] whitespace-nowrap">
          Dashboard
        </span>
        <ChevronRight className="w-3 h-3 text-slate-300 dark:text-zinc-700" />
        <h1 className="text-xs font-black text-slate-900 dark:text-zinc-100 uppercase whitespace-nowrap">
          AFM
        </h1>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative hidden lg:block">
          <button
            type="button"
            onClick={() => {
              setShowFilters((prev) => !prev)
              setShowProfile(false)
            }}
            className={`flex items-center gap-3 rounded-2xl border px-4 py-2 text-[11px] font-black uppercase tracking-[0.16em] transition-all ${
              showFilters
                ? isDark
                  ? 'border-indigo-500/40 bg-indigo-500/10 text-indigo-100'
                  : 'border-indigo-300 bg-indigo-50 text-indigo-700'
                : isDark
                  ? 'border-[#1F1F1F] bg-zinc-900/50 text-zinc-300 hover:border-indigo-500/30 hover:text-indigo-100'
                  : 'border-slate-200 bg-slate-50 text-slate-600 hover:border-indigo-300 hover:text-indigo-700'
            }`}
          >
            <Filter className="h-4 w-4" />
            <span>{'\u0424\u0438\u043b\u044c\u0442\u0440\u044b'}</span>
            {activeFilterCount > 0 && (
              <span className={`inline-flex min-w-[20px] items-center justify-center rounded-full px-2 py-0.5 text-[10px] ${
                isDark ? 'bg-indigo-400/20 text-indigo-200' : 'bg-indigo-600 text-white'
              }`}>
                {activeFilterCount}
              </span>
            )}
          </button>

          {showFilters && (
            <>
              <button
                type="button"
                className="fixed inset-0 z-[89] cursor-default"
                onClick={() => setShowFilters(false)}
                aria-label="\u0417\u0430\u043a\u0440\u044b\u0442\u044c \u0444\u0438\u043b\u044c\u0442\u0440\u044b"
              />
              <div className="absolute right-0 top-full z-[95] mt-3 w-[620px] max-w-[calc(100vw-3rem)]">
                <FilterPanel
                  theme={theme}
                  filters={filters}
                  setFilters={setFilters}
                  onClose={() => setShowFilters(false)}
                />
              </div>
            </>
          )}
        </div>

        <div className="relative">
          <button
            onClick={() => {
              setShowProfile(!showProfile)
              setShowFilters(false)
            }}
            className="relative w-8 h-8 rounded-lg bg-indigo-100 dark:bg-indigo-900/40 flex items-center justify-center border border-indigo-200 dark:border-indigo-800 cursor-pointer font-black text-xs text-indigo-600 dark:text-indigo-400 hover:scale-105 active:scale-95 transition-all"
          >
            {user?.email?.charAt(0).toUpperCase() || 'U'}
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 border-2 border-white dark:border-black rounded-full"></div>
          </button>

          {showProfile && (
            <>
              <div className="fixed inset-0 z-[90]" onClick={() => setShowProfile(false)}></div>
              <div className="absolute right-0 mt-3 w-56 bg-white dark:bg-[#121212] border border-slate-200 dark:border-[#1F1F1F] rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.15)] p-2 z-[100] animate-in fade-in zoom-in-95 duration-100">
                <div className="px-3 py-3 border-b border-slate-100 dark:border-[#1F1F1F] mb-1">
                  <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                    Signed in as
                  </p>
                  <p className="text-xs font-bold text-slate-800 dark:text-zinc-200 mt-0.5 truncate">
                    {user?.email}
                  </p>
                </div>

                <button
                  onClick={toggleTheme}
                  className="w-full flex items-center justify-between px-3 py-2.5 rounded-xl hover:bg-slate-50 dark:hover:bg-zinc-900 text-xs font-bold transition-all"
                >
                  <div className="flex items-center gap-2 text-slate-600 dark:text-zinc-400">
                    <Moon className="w-3.5 h-3.5" />
                    <span>Dark Mode</span>
                  </div>
                  <div className={`w-7 h-4 rounded-full relative transition-colors ${isDark ? 'bg-indigo-600' : 'bg-slate-200 dark:bg-zinc-800'}`}>
                    <div className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-all shadow-sm ${isDark ? 'left-[14px]' : 'left-0.5'}`}></div>
                  </div>
                </button>

                <button className="w-full flex items-center gap-2 px-3 py-2.5 rounded-xl hover:bg-slate-50 dark:hover:bg-zinc-900 text-xs font-bold transition-all">
                  <Settings className="w-3.5 h-3.5" />
                  <span>Settings</span>
                </button>

                <div className="h-px bg-slate-100 dark:bg-[#1F1F1F] my-1.5 mx-2"></div>

                <button
                  onClick={onLogout}
                  className="w-full flex items-center gap-2 px-3 py-2.5 rounded-xl hover:bg-rose-50 dark:hover:bg-rose-950/20 text-xs font-bold text-rose-500 transition-all"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Log out</span>
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}

export default Navbar
