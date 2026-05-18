import React, { useState, useRef, useEffect, useMemo } from 'react'
import {
  Database,
  ArrowUpDown,
  Download,
  ChevronLeft,
  ChevronRight,
  ArrowUpRight,
  ArrowDownRight,
  ArrowUp,
  ChevronUp,
  Maximize2,
  Minimize2,
} from 'lucide-react'

const TENGE = '\u20B8'

const bankColumns = [
  { key: 'category', label: 'КАТЕГОРИЯ', width: 'min-w-[160px]' },
  { key: 'operation_type', label: 'ВИД ОПЕРАЦИИ', width: 'min-w-[180px]' },
  { key: 'date', label: 'ДАТА', width: 'w-[140px]' },
  { key: 'sender', label: 'ОТПРАВИТЕЛЬ', width: 'min-w-[220px]' },
  { key: 'recipient', label: 'ПОЛУЧАТЕЛЬ', width: 'min-w-[220px]' },
  { key: 'purpose', label: 'НАЗНАЧЕНИЕ', width: 'min-w-[320px]' },
  { key: 'currency', label: 'ВАЛЮТА', width: 'w-[90px]' },
  { key: 'debit', label: 'РАСХОД', width: 'w-[130px]' },
  { key: 'credit', label: 'ПОСТУПЛЕНИЕ', width: 'w-[130px]' },
  { key: 'amount_tenge', label: 'СУММА (ТЕНГЕ)', width: 'w-[150px]' },
]

const esfRawColumns = [
  { key: 'buyer_iin_bin', label: 'ИИН/БИН ПОКУП.', width: 'min-w-[150px]' },
  { key: 'buyer_name', label: 'ПОКУПАТЕЛЬ', width: 'min-w-[220px]' },
  { key: 'supplier_iin_bin', label: 'ИИН/БИН ПОСТ.', width: 'min-w-[150px]' },
  { key: 'supplier_name', label: 'ПОСТАВЩИК', width: 'min-w-[220px]' },
  { key: 'tru_name', label: 'НАИМЕНОВАНИЕ ТРУ', width: 'min-w-[260px]' },
  { key: 'price_with_vat', label: 'ЦЕНА С НДС', width: 'w-[130px]' },
  { key: 'price_without_vat', label: 'ЦЕНА БЕЗ НДС', width: 'w-[130px]' },
  { key: 'vat_rate', label: 'СТАВКА НДС', width: 'w-[110px]' },
  { key: 'unit', label: 'ЕД. ИЗМ.', width: 'w-[120px]' },
  { key: 'quantity', label: 'КОЛ-ВО', width: 'w-[110px]' },
  { key: 'currency', label: 'КОД ВАЛ.', width: 'w-[100px]' },
  { key: 'amount_tenge', label: 'ОБЩАЯ СУММА', width: 'w-[150px]' },
]

const adminColumn = { key: 'uploaded_by_email', label: 'КТО ДОБАВИЛ', width: 'min-w-[180px]' }

const fmtNum = (v) => {
  const value = Number(v || 0)
  if (!value) return ''
  return new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 4 }).format(value)
}

function formatParty(party) {
  if (!party) return '-'
  const rawName = String(party.name || '').trim()
  const rawIin = String(party.iin_bin || '').trim()
  const rawAccount = String(party.account || '').trim()
  const name = rawName.toUpperCase() === 'UNKNOWN' ? '' : rawName
  const iin = rawIin === '000000000000' ? '' : rawIin
  const identity = rawAccount || iin || ''

  if (!name && !identity) return '-'
  if (!name) return identity
  if (!identity) return name
  return `${name}\n${identity}`
}

function ModeSwitch({ recordsMode, onRecordsModeChange }) {
  const modes = [
    { key: 'all', label: 'Совместные' },
    { key: 'bank', label: 'Банк' },
    { key: 'esf', label: 'ЭСФ' },
  ]

  return (
    <div className="flex items-center rounded-2xl border border-slate-200 bg-slate-50 p-1 dark:border-zinc-800 dark:bg-zinc-900/80">
      {modes.map((mode) => {
        const active = recordsMode === mode.key
        return (
          <button
            key={mode.key}
            type="button"
            onClick={() => onRecordsModeChange?.(mode.key)}
            className={`rounded-xl px-3 py-2 text-[9px] font-black uppercase tracking-[0.18em] transition-all ${
              active
                ? 'bg-indigo-500 text-white shadow-lg shadow-indigo-500/20'
                : 'text-slate-500 hover:text-indigo-500 dark:text-zinc-500 dark:hover:text-indigo-300'
            }`}
          >
            {mode.label}
          </button>
        )
      })}
    </div>
  )
}

function EsfSwitches({ esfDirection, esfSheet, onEsfDirectionChange, onEsfSheetChange }) {
  const directionLabel = esfDirection === 'purchase' ? 'Приобретение' : 'Реализация'
  const sheets = esfDirection === 'purchase'
    ? [
        { key: 'esf', label: 'ЭСФ' },
        { key: 'summary', label: 'Свод 8' },
        { key: 'tru', label: 'Свод ТРУ' },
      ]
    : [
        { key: 'esf', label: 'ЭСФ' },
        { key: 'summary', label: 'Свод 7' },
        { key: 'tru', label: 'Свод ТРУ' },
      ]

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        {[
          { key: 'sale', label: 'Реализация' },
          { key: 'purchase', label: 'Приобретение' },
        ].map((mode) => {
          const active = esfDirection === mode.key
          return (
            <button
              key={mode.key}
              type="button"
              onClick={() => onEsfDirectionChange?.(mode.key)}
              className={`rounded-xl px-3 py-2 text-[9px] font-black uppercase tracking-[0.18em] transition-all ${
                active
                  ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/20'
                  : 'border border-slate-200 bg-slate-50 text-slate-500 hover:text-emerald-500 dark:border-zinc-800 dark:bg-zinc-900/80 dark:text-zinc-500'
              }`}
            >
              {mode.label}
            </button>
          )
        })}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[9px] font-black uppercase tracking-[0.18em] text-slate-400 dark:text-zinc-500">
          {directionLabel}
        </span>
        {sheets.map((sheet) => {
          const active = esfSheet === sheet.key
          return (
            <button
              key={sheet.key}
              type="button"
              onClick={() => onEsfSheetChange?.(sheet.key)}
              className={`rounded-xl px-3 py-2 text-[9px] font-black uppercase tracking-[0.18em] transition-all ${
                active
                  ? 'bg-indigo-500 text-white shadow-lg shadow-indigo-500/20'
                  : 'border border-slate-200 bg-slate-50 text-slate-500 hover:text-indigo-500 dark:border-zinc-800 dark:bg-zinc-900/80 dark:text-zinc-500'
              }`}
            >
              {sheet.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}

function buildEsfSummaryColumns(esfYears = []) {
  return [
    { key: 'buyer_iin_bin', label: 'ИИН/БИН ПОКУП.', width: 'min-w-[150px]' },
    { key: 'buyer_name', label: 'ПОКУПАТЕЛЬ', width: 'min-w-[220px]' },
    { key: 'supplier_iin_bin', label: 'ИИН/БИН ПОСТ.', width: 'min-w-[150px]' },
    { key: 'supplier_name', label: 'ПОСТАВЩИК', width: 'min-w-[220px]' },
    ...esfYears.map((year) => ({
      key: `year_${year}`,
      label: String(year),
      width: 'w-[120px]',
    })),
    { key: 'overall_total', label: 'ОБЩИЙ ИТОГ', width: 'w-[150px]' },
  ]
}

function buildEsfTruColumns(esfYears = []) {
  return [
    { key: 'buyer_iin_bin', label: 'ИИН/БИН ПОКУП.', width: 'min-w-[150px]' },
    { key: 'buyer_name', label: 'ПОКУПАТЕЛЬ', width: 'min-w-[220px]' },
    { key: 'supplier_iin_bin', label: 'ИИН/БИН ПОСТ.', width: 'min-w-[150px]' },
    { key: 'supplier_name', label: 'ПОСТАВЩИК', width: 'min-w-[220px]' },
    { key: 'tru_name', label: 'НАИМЕНОВАНИЕ ТРУ', width: 'min-w-[260px]' },
    { key: 'price_with_vat', label: 'ЦЕНА С НДС', width: 'w-[130px]' },
    { key: 'price_without_vat', label: 'ЦЕНА БЕЗ НДС', width: 'w-[130px]' },
    { key: 'vat_rate', label: 'СТАВКА НДС', width: 'w-[110px]' },
    { key: 'unit', label: 'ЕД. ИЗМ.', width: 'w-[120px]' },
    { key: 'currency', label: 'КОД ВАЛ.', width: 'w-[100px]' },
    ...esfYears.map((year) => ({
      key: `qty_${year}`,
      label: `КОЛ-ВО ${year}`,
      width: 'w-[120px]',
    })),
    ...esfYears.map((year) => ({
      key: `amt_${year}`,
      label: `ОБЩАЯ СУММА ${year}`,
      width: 'w-[150px]',
    })),
    { key: 'total_quantity', label: 'ИТОГ КОЛ-ВО', width: 'w-[140px]' },
    { key: 'total_amount', label: 'ОБЩАЯ СУММА', width: 'w-[150px]' },
  ]
}

function isEsfNumericColumn(key) {
  return /^(price_|qty_|amt_|year_|overall_total|total_|vat_rate)/.test(key)
}

function renderBankCell(row, col, isAdmin) {
  switch (col.key) {
    case 'category':
      return <span className="text-[11px] font-bold uppercase text-slate-800 dark:text-zinc-200">{row.category || '-'}</span>
    case 'operation_type':
      return <span className="text-[11px] font-bold text-slate-500 dark:text-zinc-400">{row.operation_type || '-'}</span>
    case 'date':
      return <span className="text-[11px] font-bold text-slate-400 dark:text-zinc-500 font-mono">{row.date || '-'}</span>
    case 'sender':
      return <div className="text-[11px] font-bold text-slate-700 dark:text-zinc-300 whitespace-pre-line leading-relaxed max-w-[200px]">{formatParty(row.sender)}</div>
    case 'recipient':
      return <div className="text-[11px] font-bold text-slate-700 dark:text-zinc-300 whitespace-pre-line leading-relaxed max-w-[200px]">{formatParty(row.recipient)}</div>
    case 'purpose':
      return <div className="text-[11px] font-medium text-slate-500 dark:text-zinc-400 line-clamp-2 max-w-[320px] whitespace-pre-line">{row.purpose}</div>
    case 'currency':
      return <span className="px-2 py-0.5 rounded-lg text-[9px] font-black uppercase tracking-wider bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-100 dark:border-emerald-500/20">{row.currency}</span>
    case 'debit':
      return row.debit ? <span className="text-[11px] font-black text-rose-500 dark:text-rose-400 font-mono">-{fmtNum(row.debit)}</span> : <span className="text-slate-200 dark:text-zinc-800">-</span>
    case 'credit':
      return row.credit ? <span className="text-[11px] font-black text-emerald-500 dark:text-emerald-400 font-mono">+{fmtNum(row.credit)}</span> : <span className="text-slate-200 dark:text-zinc-800">-</span>
    case 'amount_tenge':
      return <span className="text-[12px] font-black text-slate-900 dark:text-zinc-100 font-mono">{fmtNum(row.amount_tenge)} {TENGE}</span>
    case 'uploaded_by_email':
      return isAdmin ? <span className="text-[10px] font-bold text-slate-400 dark:text-zinc-600 truncate block max-w-[150px]">{row.uploaded_by_email || '-'}</span> : null
    default:
      return <span className="text-[11px] text-slate-500 dark:text-zinc-400">-</span>
  }
}

function renderEsfCell(row, col, labelKey) {
  const rowType = row?.row_type || 'detail'
  if (rowType !== 'detail') {
    if (col.key === labelKey) {
      return (
        <span className={`text-[11px] font-black uppercase tracking-[0.14em] ${
          rowType === 'grand_total'
            ? 'text-indigo-600 dark:text-indigo-300'
            : 'text-slate-800 dark:text-zinc-100'
        }`}>
          {row?.label || (rowType === 'grand_total' ? 'Общий итог' : 'Итог')}
        </span>
      )
    }
    if (isEsfNumericColumn(col.key)) {
      return <span className="text-[11px] font-black text-slate-900 dark:text-zinc-100 font-mono">{fmtNum(row?.[col.key]) || '-'}</span>
    }
    return <span className="text-[11px] text-transparent">.</span>
  }

  const value = row?.[col.key]
  if (col.key.includes('iin_bin')) {
    return <span className="text-[11px] font-mono font-bold text-slate-500 dark:text-zinc-400">{value || '-'}</span>
  }
  if (['buyer_name', 'supplier_name'].includes(col.key)) {
    return <div className="text-[11px] font-bold text-slate-700 dark:text-zinc-300 whitespace-pre-line leading-relaxed max-w-[220px]">{value || '-'}</div>
  }
  if (['tru_name'].includes(col.key)) {
    return <div className="text-[11px] font-medium text-slate-500 dark:text-zinc-400 max-w-[260px] whitespace-pre-line line-clamp-2">{value || '-'}</div>
  }
  if (['unit', 'currency'].includes(col.key)) {
    return <span className="text-[11px] font-bold uppercase text-slate-500 dark:text-zinc-400">{value || '-'}</span>
  }
  if (col.key === 'vat_rate') {
    return <span className="text-[11px] font-black text-indigo-500 dark:text-indigo-300 font-mono">{fmtNum(value) || '-'}{value ? '%' : ''}</span>
  }
  if (typeof value === 'number' || /^(price_|qty_|amt_|year_|overall_total|total_)/.test(col.key)) {
    return <span className="text-[11px] font-black text-slate-800 dark:text-zinc-200 font-mono">{fmtNum(value) || '-'}</span>
  }
  return <span className="text-[11px] text-slate-500 dark:text-zinc-400">{value || '-'}</span>
}

function DataTable({
  isAdmin = false,
  data = [],
  pagination = {},
  summary = {},
  recordsMode = 'bank',
  esfDirection = 'sale',
  esfSheet = 'esf',
  esfYears = [],
  loading = false,
  exportLoading = false,
  onExport,
  onRecordsModeChange,
  onEsfDirectionChange,
  onEsfSheetChange,
  sortConfig = { key: 'date', direction: 'desc' },
  onSortChange,
  onPageChange,
}) {
  const [isExpanded, setIsExpanded] = useState(false)
  const containerRef = useRef(null)

  const { page = 1, total = 0, total_pages = 0 } = pagination
  const activeColumns = useMemo(() => {
    if (recordsMode !== 'esf') return isAdmin ? [...bankColumns, adminColumn] : bankColumns
    if (esfSheet === 'summary') return buildEsfSummaryColumns(esfYears)
    if (esfSheet === 'tru') return buildEsfTruColumns(esfYears)
    return esfRawColumns
  }, [recordsMode, isAdmin, esfSheet, esfYears])

  const modeLabel = useMemo(() => {
    if (recordsMode === 'all') return 'Совместные транзакции'
    if (recordsMode === 'bank') return 'Банковские транзакции'
    if (esfSheet === 'summary') return esfDirection === 'purchase' ? 'Свод 8' : 'Свод 7'
    if (esfSheet === 'tru') return 'Свод ТРУ'
    return 'ЭСФ'
  }, [recordsMode, esfDirection, esfSheet])

  const scrollToTop = () => {
    containerRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
  }

  useEffect(() => {
    if (!isExpanded) return undefined
    document.body.style.overflow = 'hidden'
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setIsExpanded(false)
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      document.body.style.overflow = ''
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [isExpanded])

  const handleSort = (key) => {
    const descKeys = ['date', 'debit', 'credit', 'amount_tenge', 'price_with_vat', 'price_without_vat', 'quantity', 'vat_rate', 'overall_total', 'total_amount', 'total_quantity']
    const nextDirection =
      sortConfig.key === key
        ? (sortConfig.direction === 'asc' ? 'desc' : 'asc')
        : (descKeys.includes(key) ? 'desc' : 'asc')
    onSortChange?.(key, nextDirection)
  }

  const alignRightKeys = new Set(activeColumns.filter((col) => /^(price_|qty_|amt_|year_|overall_total|total_|debit|credit|amount_tenge|quantity|vat_rate)/.test(col.key)).map((col) => col.key))
  const esfLabelKey = activeColumns[0]?.key

  return (
    <div className={`flex flex-col gap-6 transition-all duration-300 ${isExpanded ? 'fixed inset-0 z-[1001] bg-slate-50/95 dark:bg-zinc-950/98 backdrop-blur-md p-6 lg:p-8 xl:p-10' : ''}`}>
      <div className={`bento-tile overflow-hidden flex flex-col shadow-2xl transition-all duration-300 ${isExpanded ? 'flex-1 border-none bg-white dark:bg-zinc-900 ring-1 ring-slate-200 dark:ring-zinc-800' : ''}`}>
        <div className="flex items-center justify-between gap-4 px-6 py-5 border-b border-slate-100 dark:border-zinc-800/50">
          <div className="flex min-w-0 items-start gap-4">
            <div className="p-2 rounded-xl bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">
              <Database className="w-4 h-4" />
            </div>
            <div className="flex flex-col gap-3">
              <div className="flex items-start gap-3">
                <div>
                <h2 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500 dark:text-zinc-500">
                  {modeLabel}
                </h2>
                <p className="text-[9px] font-bold text-slate-400 dark:text-zinc-600 uppercase tracking-widest mt-0.5">
                  {total.toLocaleString()} записей обнаружено
                </p>
                </div>
                <ModeSwitch recordsMode={recordsMode} onRecordsModeChange={onRecordsModeChange} />
              </div>
              <div className="flex flex-col gap-3">
                {recordsMode === 'esf' && (
                  <EsfSwitches
                    esfDirection={esfDirection}
                    esfSheet={esfSheet}
                    onEsfDirectionChange={onEsfDirectionChange}
                    onEsfSheetChange={onEsfSheetChange}
                  />
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5 px-2 py-1 bg-slate-50 dark:bg-zinc-900 border border-slate-100 dark:border-zinc-800 rounded-xl">
              <button disabled={page <= 1} onClick={() => onPageChange?.(page - 1)} className="p-1 px-1.5 text-slate-400 hover:text-indigo-500 disabled:opacity-20 transition-all shrink-0" title="Назад">
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-zinc-500 min-w-[60px] text-center border-x border-slate-100 dark:border-zinc-800/50 px-2 mx-1">
                {page} / {total_pages || 1}
              </span>
              <button disabled={page >= total_pages} onClick={() => onPageChange?.(page + 1)} className="p-1 px-1.5 text-slate-400 hover:text-indigo-500 disabled:opacity-20 transition-all shrink-0" title="Вперед">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <button
              type="button"
              onClick={onExport}
              disabled={exportLoading}
              className="p-2.5 aspect-square bg-slate-50 dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl text-slate-600 dark:text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/30 transition-all disabled:opacity-50"
              title="Экспорт"
            >
              {exportLoading ? <span className="w-3.5 h-3.5 border-2 border-emerald-500 border-t-transparent animate-spin rounded-full" /> : <Download className="w-3.5 h-3.5" />}
            </button>

            <button
              type="button"
              onClick={() => setIsExpanded(!isExpanded)}
              className={`p-2.5 aspect-square transition-all border rounded-xl flex items-center justify-center ${
                isExpanded
                  ? 'bg-rose-50 dark:bg-rose-500/10 text-rose-500 border-rose-500/30 hover:bg-rose-500 hover:text-white'
                  : 'bg-indigo-500 text-white border-indigo-600 hover:bg-indigo-600'
              }`}
              title={isExpanded ? 'Закрыть' : 'На весь экран'}
            >
              {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {loading && (
          <div className="flex flex-col items-center justify-center py-24 gap-4">
            <div className="w-8 h-8 border-4 border-indigo-500 border-t-transparent animate-spin rounded-full" />
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Синхронизация данных...</span>
          </div>
        )}

        {!loading && data.length === 0 && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <Database className="w-12 h-12 text-slate-100 dark:text-zinc-900 mb-4" />
            <span className="text-xs font-bold text-slate-400 dark:text-zinc-600">Данные не найдены</span>
          </div>
        )}

        {!loading && data.length > 0 && (
          <div
            ref={containerRef}
            className={`overflow-x-auto overflow-y-auto custom-scrollbar transition-all duration-300 relative scroll-smooth ${
              isExpanded ? 'flex-1 min-h-0' : 'max-h-[520px]'
            }`}
          >
            <table className="w-full border-collapse">
              <thead className="bg-slate-50/50 dark:bg-zinc-900/40 sticky top-0 z-20">
                <tr>
                  {activeColumns.map((col) => (
                    <th
                      key={col.key}
                      onClick={() => handleSort(col.key)}
                      className={`px-6 py-4 text-left text-[9px] font-black uppercase tracking-widest text-slate-400 border-b border-slate-100 dark:border-zinc-800/50 cursor-pointer group select-none whitespace-nowrap ${col.width}`}
                    >
                      <div className="flex items-center gap-2">
                        {col.label}
                        <ArrowUpDown className={`w-3 h-3 transition-colors ${
                          sortConfig.key === col.key ? 'text-indigo-500' : 'text-slate-300 dark:text-zinc-800 opacity-0 group-hover:opacity-100'
                        }`} />
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50 dark:divide-zinc-900/30">
                {data.map((row) => (
                  <tr
                    key={row.id}
                    className={`group transition-colors ${
                      row?.row_type === 'grand_total'
                        ? 'bg-indigo-50/70 dark:bg-indigo-500/10'
                        : row?.row_type === 'subtotal'
                          ? 'bg-slate-100/80 dark:bg-zinc-800/60'
                          : 'hover:bg-slate-50/50 dark:hover:bg-zinc-900/30'
                    }`}
                  >
                    {activeColumns.map((col) => (
                      <td
                        key={col.key}
                        className={`px-6 py-4 ${
                          alignRightKeys.has(col.key) ? 'text-right' : ''
                        } ${
                          row?.row_type === 'grand_total'
                            ? 'border-t border-indigo-200 dark:border-indigo-500/20'
                            : row?.row_type === 'subtotal'
                              ? 'border-t border-slate-200 dark:border-zinc-700'
                              : ''
                        }`}
                      >
                        {recordsMode !== 'esf' ? renderBankCell(row, col, isAdmin) : renderEsfCell(row, col, esfLabelKey)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>

            {isExpanded && (
              <button onClick={scrollToTop} className="fixed bottom-24 right-12 p-3 bg-indigo-500 text-white rounded-full shadow-lg hover:bg-indigo-600 transition-all z-30 animate-in fade-in slide-in-from-bottom-4 duration-300" title="Наверх">
                <ArrowUp className="w-5 h-5" />
              </button>
            )}

            {!isExpanded && data.length > 8 && (
              <div className="absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t from-white dark:from-zinc-950 to-transparent pointer-events-none flex items-end justify-center pb-2">
                <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest animate-bounce">
                  <ChevronUp className="w-4 h-4 inline mr-1" /> Slide down for more
                </span>
              </div>
            )}
          </div>
        )}

        <div className="px-6 py-4 bg-slate-50/30 dark:bg-zinc-900/10 border-t border-slate-100 dark:border-zinc-800/50 flex items-center justify-between">
          <div className="flex items-center gap-4 text-[10px] font-bold text-slate-400 dark:text-zinc-600 uppercase tracking-widest">
            <span>Всего {total.toLocaleString()} операций</span>
            <div className="h-3 w-[1px] bg-slate-200 dark:bg-zinc-800" />
            <span>Сортировка: {sortConfig.key === 'date' ? 'По дате' : 'По выбранной колонке'}</span>
          </div>
        </div>
      </div>

      {!isExpanded && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
          <div className="bento-tile p-6 flex items-center justify-between">
            <div>
              <p className="text-[9px] font-black underline decoration-rose-500/30 underline-offset-4 uppercase tracking-[0.2em] text-slate-400 dark:text-zinc-500 mb-2">
                Общий расход
              </p>
              <h3 className="text-2xl font-black text-rose-500 dark:text-rose-400 leading-none">
                -{fmtNum(summary.total_debit)} <span className="text-[14px] font-bold text-slate-400">{TENGE}</span>
              </h3>
            </div>
            <div className="w-12 h-12 bg-rose-50 dark:bg-rose-500/10 rounded-2xl flex items-center justify-center text-rose-500">
              <ArrowDownRight className="w-6 h-6" />
            </div>
          </div>

          <div className="bento-tile p-6 flex items-center justify-between">
            <div>
              <p className="text-[9px] font-black underline decoration-emerald-500/30 underline-offset-4 uppercase tracking-[0.2em] text-slate-400 dark:text-zinc-500 mb-2">
                Общее поступление
              </p>
              <h3 className="text-2xl font-black text-emerald-500 dark:text-emerald-400 leading-none">
                +{fmtNum(summary.total_credit)} <span className="text-[14px] font-bold text-slate-400">{TENGE}</span>
              </h3>
            </div>
            <div className="w-12 h-12 bg-emerald-50 dark:bg-emerald-500/10 rounded-2xl flex items-center justify-center text-emerald-500">
              <ArrowUpRight className="w-6 h-6" />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DataTable
