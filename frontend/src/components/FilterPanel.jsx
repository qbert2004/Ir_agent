import React from 'react'
import { RotateCcw } from 'lucide-react'

const EMPTY_FILTERS = {
  date: '',
  category: '',
  search: '',
  minAmount: '',
  maxAmount: '',
  currency: '',
  sender: '',
  recipient: '',
}

function FilterPanel({ theme, filters, setFilters, onClose }) {
  const isDark = theme === 'dark'
  const activeFilterCount = Object.values(filters || {}).filter((value) => value !== '').length

  const handleChange = (event) => {
    const { name, value } = event.target
    setFilters((prev) => ({ ...prev, [name]: value }))
  }

  const handleReset = () => {
    setFilters(EMPTY_FILTERS)
  }

  const inputClass = `w-full rounded-2xl border px-4 py-3 text-[11px] font-bold transition-all outline-none ${
    isDark
      ? 'border-[#1F1F1F] bg-[#111114] text-white placeholder:text-zinc-600 focus:border-indigo-500/50'
      : 'border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:border-indigo-400'
  }`

  const labelClass = `mb-2 block text-[10px] font-black uppercase tracking-[0.22em] ${
    isDark ? 'text-zinc-500' : 'text-slate-400'
  }`

  return (
    <div
      className={`w-full rounded-[24px] border p-5 shadow-[0_24px_60px_rgba(0,0,0,0.18)] ${
        isDark ? 'border-[#1F1F1F] bg-[#101014]' : 'border-slate-200 bg-white'
      }`}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className={`text-[10px] font-black uppercase tracking-[0.24em] ${isDark ? 'text-zinc-500' : 'text-slate-400'}`}>
            {'\u0424\u0438\u043b\u044c\u0442\u0440\u044b'}
          </div>
          <p className={`mt-2 max-w-md text-xs leading-5 ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>
            {'\u042d\u0442\u0438 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b \u043f\u0440\u0438\u043c\u0435\u043d\u044f\u044e\u0442\u0441\u044f \u0438 \u043a \u0442\u0440\u0430\u043d\u0437\u0430\u043a\u0446\u0438\u044f\u043c, \u0438 \u043a\u043e \u0432\u0441\u0435\u0439 \u0430\u043d\u0430\u043b\u0438\u0442\u0438\u043a\u0435 \u043f\u0440\u043e\u0435\u043a\u0442\u0430.'}
          </p>
        </div>

        <button
          type="button"
          onClick={handleReset}
          className={`inline-flex items-center gap-2 rounded-2xl border px-3 py-2 text-[10px] font-black uppercase tracking-[0.16em] transition-all ${
            isDark
              ? 'border-[#1F1F1F] bg-zinc-950/60 text-zinc-300 hover:bg-zinc-900'
              : 'border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100'
          }`}
        >
          <RotateCcw className="h-3.5 w-3.5" />
          {'\u0421\u0431\u0440\u043e\u0441\u0438\u0442\u044c'}
        </button>
      </div>

      {activeFilterCount > 0 && (
        <div className={`mt-4 rounded-2xl border px-4 py-3 text-[11px] font-bold ${
          isDark
            ? 'border-indigo-500/20 bg-indigo-500/10 text-indigo-200'
            : 'border-indigo-200 bg-indigo-50 text-indigo-700'
        }`}>
          {'\u0410\u043a\u0442\u0438\u0432\u043d\u044b\u0445 \u0444\u0438\u043b\u044c\u0442\u0440\u043e\u0432: '}{activeFilterCount}
        </div>
      )}

      <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
        <label className="block">
          <span className={labelClass}>{'\u0414\u0430\u0442\u0430'}</span>
          <input type="text" name="date" placeholder="04.02.2026" value={filters.date} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block">
          <span className={labelClass}>{'\u041a\u0430\u0442\u0435\u0433\u043e\u0440\u0438\u044f'}</span>
          <input type="text" name="category" placeholder={'\u041a\u0430\u0442\u0435\u0433\u043e\u0440\u0438\u044f'} value={filters.category} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block md:col-span-2">
          <span className={labelClass}>{'\u041f\u043e\u0438\u0441\u043a'}</span>
          <input type="text" name="search" placeholder={'\u041f\u043e\u0438\u0441\u043a \u043f\u043e \u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044e'} value={filters.search} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block">
          <span className={labelClass}>{'\u0412\u0430\u043b\u044e\u0442\u0430'}</span>
          <input type="text" name="currency" placeholder="KZT, USD" value={filters.currency} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block">
          <span className={labelClass}>{'\u041e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u0435\u043b\u044c'}</span>
          <input type="text" name="sender" placeholder={'\u0418\u0418\u041d / \u0411\u0418\u041d / \u0438\u043c\u044f'} value={filters.sender} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block">
          <span className={labelClass}>{'\u041c\u0438\u043d. \u0441\u0443\u043c\u043c\u0430'}</span>
          <input type="number" name="minAmount" placeholder="0" value={filters.minAmount} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block">
          <span className={labelClass}>{'\u041c\u0430\u043a\u0441. \u0441\u0443\u043c\u043c\u0430'}</span>
          <input type="number" name="maxAmount" placeholder="999999" value={filters.maxAmount} onChange={handleChange} className={inputClass} />
        </label>
        <label className="block md:col-span-2">
          <span className={labelClass}>{'\u041f\u043e\u043b\u0443\u0447\u0430\u0442\u0435\u043b\u044c'}</span>
          <input type="text" name="recipient" placeholder={'\u0418\u0418\u041d / \u0411\u0418\u041d / \u0438\u043c\u044f'} value={filters.recipient} onChange={handleChange} className={inputClass} />
        </label>
      </div>

      <div className="mt-5 flex justify-end">
        <button
          type="button"
          onClick={() => onClose?.()}
          className={`rounded-2xl px-4 py-3 text-sm font-black transition-all ${
            isDark
              ? 'bg-indigo-500 text-white hover:bg-indigo-400'
              : 'bg-indigo-600 text-white hover:bg-indigo-500'
          }`}
        >
          {'\u0413\u043e\u0442\u043e\u0432\u043e'}
        </button>
      </div>
    </div>
  )
}

export default FilterPanel
