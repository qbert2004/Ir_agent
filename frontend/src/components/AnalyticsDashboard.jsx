import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, Rectangle,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  fetchTimeSeries,
  fetchTimeSeriesTransactions,
  fetchSummary,
  fetchTopExpenses,
  fetchTopExpenseTransactions,
  fetchTopCounterparties,
  fetchCashTop,
  fetchCashTransactions,
  fetchCounterpartyTransactions,
  fetchCounterpartyGraph,
  fetchCategorySummary,
  fetchTransactions,
} from '../services/api'
import { autoFitWorksheetColumns } from '../utils/xlsx'

import {
  Filter, Database, ArrowDownRight, ArrowUpRight, Activity, Sparkles, ListTodo, ArrowRight, FileSpreadsheet, FileText, Printer
} from 'lucide-react'

const DONUT_COLORS = ['#6366f1', '#4f46e5', '#4338ca', '#3730a3', '#312e81', '#1e1b4b', '#1e1b4b', '#4f46e5', '#6366f1', '#818cf8']
const CASH_WITHDRAWAL_COLORS = [
  '#ef4444', '#dc2626', '#b91c1c', '#991b1b', '#7f1d1d',
  '#f87171', '#fb923c', '#fca5a5', '#fecaca',
]
const CASH_DEPOSIT_COLORS = [
  '#10b981', '#059669', '#047857', '#065f46', '#064e3b',
  '#34d399', '#6ee7b7', '#a7f3d0', '#d1fae5',
]
const CATEGORY_MUTED_COLORS = [
  '#6366f1', '#4f46e5', '#4338ca',
  '#3730a3', '#312e81', '#1e1b4b',
  '#818cf8', '#a5b4fc', '#c7d2fe',
  '#e0e7ff', '#6366f1', '#4f46e5',
]

const fmt = (v) => {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)}K`
  return String(v)
}

const fmtFull = (v) => new Intl.NumberFormat('ru-RU').format(v || 0)
const TENGE = '\u20B8'
const compactLabel = (value) => String(value || '—').replace(/\s+/g, ' ').trim()
const EllipsisLabel = (value, max = 22) => {
  const text = compactLabel(value)
  return text.length > max ? `${text.slice(0, max - 3)}...` : text
}

const PERIOD_MAP = { 'Год': 'year', 'Месяц': 'month', 'День': 'day' }

function normalizeAgentName(value) {
  return compactLabel(value)
    .replace(/^"+|"+$/g, '')
    .replace(/^'+|'+$/g, '')
    .toLowerCase()
}

function mergeAgentRows(rows, valueKey) {
  const emptyNames = new Set(['', normalizeAgentName('—'), normalizeAgentName('вЂ”')])
  const merged = new Map()
  rows.forEach((row) => {
    const nameKey = normalizeAgentName(row.name)
    const key = !emptyNames.has(nameKey)
      ? `name:${nameKey}`
      : row.iinBin
        ? `iin:${row.iinBin}`
        : row.account
          ? `acc:${row.account}`
          : `row:${merged.size}`
    const current = merged.get(key)
    if (!current) {
      merged.set(key, { ...row })
      return
    }
    current[valueKey] = Number(current[valueKey] || 0) + Number(row[valueKey] || 0)
    current.txCount = Number(current.txCount || 0) + Number(row.txCount || 0)
    current.amount = Number(current.amount || 0) + Number(row.amount || 0)
    current.turnover = Number(current.turnover || 0) + Number(row.turnover || 0)
    current.iinBin = current.iinBin || row.iinBin || ''
    current.account = current.account || row.account || ''
    current.lastDate = current.lastDate || row.lastDate || ''
  })
  return [...merged.values()].sort((a, b) => Number(b[valueKey] || 0) - Number(a[valueKey] || 0))
}

const CATEGORY_EXPORT_COLUMNS = [
  { header: 'Дата', value: (tx) => tx.date || '' },
  { header: 'Отправитель', value: (tx) => tx.sender?.name || '' },
  { header: 'Счет отправителя', value: (tx) => tx.sender?.account || '' },
  { header: 'ИИН/БИН отправителя', value: (tx) => tx.sender?.iin_bin || '' },
  { header: 'Получатель', value: (tx) => tx.recipient?.name || '' },
  { header: 'Счет получателя', value: (tx) => tx.recipient?.account || '' },
  { header: 'ИИН/БИН получателя', value: (tx) => tx.recipient?.iin_bin || '' },
  { header: 'Назначение', value: (tx) => tx.purpose || '' },
  { header: 'Валюта', value: (tx) => tx.currency || 'KZT' },
  { header: 'Сумма', value: (tx) => Number(tx.amount_tenge || 0) },
]

function escapeExportHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function safeExportFileName(value) {
  return String(value || 'category-transactions')
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, '-')
    .slice(0, 90)
}

function downloadExportBlob(content, fileName, type) {
  const blob = content instanceof Blob ? content : new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function buildCategoryExportRows(rows) {
  return rows.map((tx) => CATEGORY_EXPORT_COLUMNS.reduce((acc, col) => {
    acc[col.header] = col.value(tx)
    return acc
  }, {}))
}

function buildTransactionExportRows(rows) {
  return rows.map((tx) => ({
    'Дата': tx.date || '',
    'Отправитель': tx.sender_name || tx.sender?.name || '',
    'Счет отправителя': tx.sender_account || tx.sender?.account || '',
    'ИИН/БИН отправителя': tx.sender_iin_bin || tx.sender?.iin_bin || '',
    'Получатель': tx.recipient_name || tx.recipient?.name || '',
    'Счет получателя': tx.recipient_account || tx.recipient?.account || '',
    'ИИН/БИН получателя': tx.recipient_iin_bin || tx.recipient?.iin_bin || '',
    'Назначение': tx.purpose || '',
    'Валюта': tx.currency || 'KZT',
    'Сумма': Number(tx.amount_tenge || 0),
  }))
}

function buildCategoryExportHtml(title, rows) {
  const totalAmount = rows.reduce((sum, tx) => sum + Number(tx.amount_tenge || 0), 0)
  const bodyRows = rows.map((tx) => (
    `<tr>${CATEGORY_EXPORT_COLUMNS.map((col) => `<td>${escapeExportHtml(col.value(tx))}</td>`).join('')}</tr>`
  )).join('')

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>${escapeExportHtml(title)}</title>
  <style>
    body { font-family: Arial, sans-serif; color: #111827; }
    h1 { font-size: 20px; margin: 0 0 8px; }
    .meta { color: #4b5563; font-size: 12px; margin-bottom: 14px; }
    table { width: 100%; border-collapse: collapse; font-size: 10px; }
    th, td { border: 1px solid #d1d5db; padding: 6px; vertical-align: top; }
    th { background: #f3f4f6; text-align: left; }
  </style>
</head>
<body>
  <h1>${escapeExportHtml(title || 'Транзакции категории')}</h1>
  <div class="meta">
    <div>Строк: ${rows.length}</div>
    <div>Общая сумма: ${escapeExportHtml(fmtFull(totalAmount))} ${TENGE}</div>
    <div>Дата выгрузки: ${escapeExportHtml(new Date().toLocaleString('ru-RU'))}</div>
  </div>
  <table>
    <thead><tr>${CATEGORY_EXPORT_COLUMNS.map((col) => `<th>${escapeExportHtml(col.header)}</th>`).join('')}</tr></thead>
    <tbody>${bodyRows || `<tr><td colspan="${CATEGORY_EXPORT_COLUMNS.length}">Нет данных</td></tr>`}</tbody>
  </table>
</body>
</html>`
}

function buildGraphLayout(nodes, width = 900, height = 520) {
  const centerX = width / 2
  const centerY = height / 2
  const maxLevel = Math.max(0, ...nodes.map((n) => n.level || 0))

  const levels = Array.from({ length: maxLevel + 1 }, () => [])
  nodes.forEach((n) => {
    const lvl = Math.max(0, Math.min(maxLevel, Number(n.level || 0)))
    levels[lvl].push(n)
  })

  const positioned = {}
  levels.forEach((levelNodes, level) => {
    if (level === 0 && levelNodes.length) {
      const n = levelNodes[0]
      positioned[n.id] = { ...n, x: centerX, y: centerY, r: 18 }
      return
    }

    const radius = 90 + level * 100
    const count = levelNodes.length
    levelNodes.forEach((n, idx) => {
      const angle = ((Math.PI * 2) / Math.max(1, count)) * idx - Math.PI / 2
      positioned[n.id] = {
        ...n,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        r: Math.max(10, Math.min(22, 10 + Math.log10((n.total_turnover || 1) + 1) * 4)),
      }
    })
  })

  return positioned
}

function splitLabelLines(text, maxChars = 22) {
  const src = String(text || '').trim()
  if (!src) return ['—']
  const words = src.split(/\s+/)
  const lines = []
  let current = ''

  for (const w of words) {
    if (!current) {
      current = w
      continue
    }
    if ((current + ' ' + w).length <= maxChars) {
      current += ` ${w}`
    } else {
      lines.push(current)
      current = w
    }
  }
  if (current) lines.push(current)
  return lines
}

function DonutWithList({
  title,
  iconType,
  data,
  total,
  isDark,
  headingText,
  subtitleText,
  tooltipStyle,
  onTxClick,
  onToggle,
}) {
  const Theme = isDark ? 'dark' : 'light'
  const iconSurfaceClass = iconType === 'withdrawal'
    ? 'bg-rose-50 dark:bg-rose-500/10 text-rose-500'
    : 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-500'

  return (
    <div
      className="bento-tile flex h-full min-h-[400px] flex-col p-6"
    >
      <div className="flex items-center justify-between mb-6">
        <div 
          className="flex items-center gap-3 cursor-pointer group"
          onClick={onToggle}
          title="Нажмите для переключения"
        >
          <div className={`p-2 rounded-xl transition-all group-hover:scale-110 ${iconSurfaceClass}`}>
            {iconType === 'withdrawal' ? <ArrowDownRight className="w-4 h-4" /> : <ArrowUpRight className="w-4 h-4" />}
          </div>
          <h2 className={`${headingText} group-hover:text-indigo-500 transition-colors`}>{title}</h2>
        </div>
        <div className="flex flex-col items-end">
          <span className={subtitleText}>ИТОГО</span>
          <span className={`text-xs font-black font-mono ${isDark ? 'text-zinc-100' : 'text-slate-900'}`}>
            {fmtFull(total)} {TENGE}
          </span>
        </div>
      </div>

      <div className="flex-1 flex flex-col lg:flex-row items-center gap-6 min-h-0">
        <div className="w-full lg:w-1/2 h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="amount"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={2}
                stroke="none"
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(value) => [`${fmtFull(value)} ${TENGE}`, 'Сумма']}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="w-full lg:w-1/2 space-y-3">
          {data.map((item, i) => (
            <div key={i} className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }}></span>
                <div className="min-w-0">
                  <div className={`text-[11px] font-bold truncate text-slate-700 dark:text-zinc-300`}>{item.name}</div>
                  {item.lastDate && (
                    <div className={subtitleText}>{item.lastDate}</div>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className={`text-[11px] font-black text-slate-900 dark:text-zinc-100 font-mono`}>{fmtFull(item.amount)} {TENGE}</span>
                <button
                  type="button"
                  onClick={() => onTxClick?.(item)}
                  className="px-2 py-0.5 rounded-lg border border-slate-100 dark:border-zinc-800 bg-slate-50 dark:bg-zinc-900 text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-zinc-500 hover:text-indigo-500 transition-colors"
                >
                  {item.txCount}
                </button>
              </div>
            </div>
          ))}
          {data.length === 0 && (
            <div className={subtitleText}>Нет данных</div>
          )}
        </div>
      </div>

      <div className="mt-4 pt-4 border-t border-slate-50 dark:border-zinc-900 flex items-center justify-between">
        <span className={subtitleText}>Итоговый оборот</span>
        <span className="text-[11px] font-black text-slate-900 dark:text-zinc-100">{fmtFull(total)} {TENGE}</span>
      </div>
    </div>
  )
}

function AnalyticsDashboard({ theme, filters = {} }) {
  const isDark = theme === 'dark'
  const activeFilters = filters || {}
  const [timePeriod, setTimePeriod] = useState('Месяц')
  const [bottomToggle, setBottomToggle] = useState('Расходы')
  const [chartZoom, setChartZoom] = useState(1)
  const [categoryZoom, setCategoryZoom] = useState(1)
  const [kpiValueFontSize, setKpiValueFontSize] = useState(24)

  const [chartData, setChartData] = useState([])
  const [kpi, setKpi] = useState({ total_credit: 0, total_debit: 0, total_turnover: 0, total_transactions: 0, period: { from: '—', to: '—' } })
  const [expenseData, setExpenseData] = useState({ data: [], total: 0 })
  const [counterparties, setCounterparties] = useState([])
  const [cashWithdrawals, setCashWithdrawals] = useState({ data: [], total: 0 })
  const [cashDeposits, setCashDeposits] = useState({ data: [], total: 0 })
  const [categorySummary, setCategorySummary] = useState([])
  const [cashModal, setCashModal] = useState({
    open: false,
    title: '',
    loading: false,
    rows: [],
    total: 0,
    error: '',
  })
  const [cashTxSort, setCashTxSort] = useState({
    field: 'date',
    direction: 'desc',
  })
  const [categoryModal, setCategoryModal] = useState({
    open: false,
    loading: false,
    title: '',
    rows: [],
    total: 0,
    error: '',
  })
  const [categoryTxSort, setCategoryTxSort] = useState({
    field: 'amount_tenge',
    direction: 'desc',
  })
  const [investigationModal, setInvestigationModal] = useState({
    open: false,
    loading: false,
    error: '',
    centerName: '',
    nodes: [],
    edges: [],
  })
  const [investigationZoom, setInvestigationZoom] = useState(1)
  const [AnalyticsBootstrapped, setAnalyticsBootstrapped] = useState(false)
  const [cashToggle, setCashToggle] = useState('withdrawal')
  const pinchStartDistanceRef = useRef(null)
  const pinchStartZoomRef = useRef(1)
  const investigationViewportRef = useRef(null)
  const kpiGridRef = useRef(null)

  useEffect(() => {
    const grid = kpiGridRef.current
    if (!grid) return undefined

    const calculateFontSize = () => {
      const cardWidths = Array.from(grid.children)
        .map((child) => child.getBoundingClientRect().width)
        .filter((width) => width > 0)
      if (!cardWidths.length) return

      const labels = [
        { value: fmtFull(kpi.total_credit), unit: TENGE },
        { value: kpi.total_transactions.toLocaleString(), unit: 'ЕД.' },
        { value: `−${fmtFull(kpi.total_debit)}`, unit: TENGE },
        { value: fmtFull(kpi.total_turnover), unit: TENGE },
      ]
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      if (!ctx) return

      const baseSize = 24
      const valueFont = `900 ${baseSize}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace`
      const unitFont = '700 14px ui-sans-serif, system-ui, sans-serif'
      const maxTextWidth = labels.reduce((max, label) => {
        ctx.font = valueFont
        const valueWidth = ctx.measureText(label.value).width
        ctx.font = unitFont
        const unitWidth = ctx.measureText(label.unit).width
        return Math.max(max, valueWidth + 6 + unitWidth)
      }, 1)
      const availableWidth = Math.max(120, Math.min(...cardWidths) - 40)
      const nextSize = Math.max(15, Math.min(baseSize, Math.floor(baseSize * (availableWidth / maxTextWidth))))

      setKpiValueFontSize((current) => (current === nextSize ? current : nextSize))
    }

    calculateFontSize()
    const observer = new ResizeObserver(calculateFontSize)
    observer.observe(grid)
    Array.from(grid.children).forEach((child) => observer.observe(child))
    window.addEventListener('resize', calculateFontSize)

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', calculateFontSize)
    }
  }, [kpi.total_credit, kpi.total_debit, kpi.total_turnover, kpi.total_transactions])

  const loadTimeSeries = useCallback(async (period) => {
    try {
      const res = await fetchTimeSeries(PERIOD_MAP[period] || 'month', undefined, undefined, activeFilters)
      setChartData(res.data || [])
    } catch (e) { console.error(e) }
  }, [activeFilters])

  const loadSummary = useCallback(async () => {
    try { setKpi(await fetchSummary(undefined, undefined, activeFilters)) }
    catch (e) { console.error(e) }
  }, [activeFilters])

  const loadExpenses = useCallback(async (type) => {
    try {
      const apiType = type === 'Расходы' ? 'debit' : 'credit'
      setExpenseData(await fetchTopExpenses(apiType, 10, activeFilters))
    } catch (e) { console.error(e) }
  }, [activeFilters])

  const loadCounterparties = useCallback(async () => {
    try {
      const res = await fetchTopCounterparties(10, activeFilters)
      setCounterparties(res.data || [])
    } catch (e) { console.error(e) }
  }, [activeFilters])

  const loadCashPanels = useCallback(async () => {
    try {
      const withdrawalRes = await fetchCashTop('withdrawal', 10, activeFilters)
      const depositRes = await fetchCashTop('deposit', 10, activeFilters)
      setCashWithdrawals(withdrawalRes || { data: [], total: 0 })
      setCashDeposits(depositRes || { data: [], total: 0 })
    } catch (e) { console.error(e) }
  }, [activeFilters])

  const loadCategorySummary = useCallback(async () => {
    try {
      const res = await fetchCategorySummary(24, activeFilters)
      setCategorySummary(res?.data || [])
    } catch (e) { console.error(e) }
  }, [activeFilters])

  const openCashTransactions = useCallback(async (type, item) => {
    if (!item?.iinBin) return

    setCashModal({
      open: true,
      title: type === 'withdrawal' ? 'Снятие наличных' : 'Пополнение наличными',
      loading: true,
      rows: [],
      total: 0,
      error: '',
    })

    try {
      const res = await fetchCashTransactions(type, item.iinBin, item.account, 200, activeFilters)
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        rows: res.data || [],
        total: res.total || 0,
        error: '',
      }))
    } catch (e) {
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        error: e?.message || 'Не удалось загрузить транзакции',
      }))
    }
  }, [activeFilters])

  const openCounterpartyTransactions = useCallback(async (item) => {
    if (!item?.iinBin) return

    setCashModal({
      open: true,
      title: 'Топ контрагентов',
      loading: true,
      rows: [],
      total: 0,
      error: '',
    })

    try {
      const res = await fetchCounterpartyTransactions(item.iinBin, item.account, 200, activeFilters)
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        rows: res.data || [],
        total: res.total || 0,
        error: '',
      }))
    } catch (e) {
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        error: e?.message || 'Не удалось загрузить транзакции',
      }))
    }
  }, [activeFilters])

  const openTopExpenseTransactions = useCallback(async (item) => {
    if (!item) return

    setCashModal({
      open: true,
      title: bottomToggle === 'Расходы' ? 'Топ по расходу' : 'Топ по поступлению',
      loading: true,
      rows: [],
      total: 0,
      error: '',
    })

    try {
      const apiType = bottomToggle === 'Расходы' ? 'debit' : 'credit'
      const res = await fetchTopExpenseTransactions(
        apiType,
        item.iinBin || '',
        item.account || '',
        item.name || '',
        200,
        activeFilters,
      )
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        rows: res.data || [],
        total: res.total || 0,
        error: '',
      }))
    } catch (e) {
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        error: e?.message || 'Не удалось загрузить транзакции',
      }))
    }
  }, [activeFilters, bottomToggle])

  const openCategoryTransactions = useCallback(async (categoryName) => {
    if (!categoryName) return
    setCategoryModal({
      open: true,
      loading: true,
      title: `Категория: ${categoryName}`,
      rows: [],
      total: 0,
      error: '',
    })
    try {
      const res = await fetchTransactions({
        ...activeFilters,
        category: categoryName,
        page: 1,
        perPage: 500,
      })
      setCategoryModal((prev) => ({
        ...prev,
        loading: false,
        rows: res?.data || [],
        total: res?.pagination?.total || 0,
        error: '',
      }))
    } catch (e) {
      setCategoryModal((prev) => ({
        ...prev,
        loading: false,
        error: e?.message || 'Не удалось загрузить транзакции категории',
      }))
    }
  }, [activeFilters])

  const openTimePointTransactions = useCallback(async (point) => {
    if (!point?.date) return
    const periodApi = PERIOD_MAP[timePeriod] || 'month'
    const title = `Период: ${point.label || point.date}`

    setCashModal({
      open: true,
      title,
      loading: true,
      rows: [],
      total: 0,
      error: '',
    })

    try {
      const res = await fetchTimeSeriesTransactions(periodApi, point.date, 200, activeFilters)
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        rows: res.data || [],
        total: res.total || 0,
        error: '',
      }))
    } catch (e) {
      setCashModal((prev) => ({
        ...prev,
        loading: false,
        error: e?.message || 'Не удалось загрузить транзакции периода',
      }))
    }
  }, [activeFilters, timePeriod])

  const openInvestigationGraph = useCallback(async (item) => {
    if (!item?.iinBin) return
    setInvestigationModal({
      open: true,
      loading: true,
      error: '',
      centerName: item.name || 'Контрагент',
      nodes: [],
      edges: [],
    })
    setInvestigationZoom(1)

    try {
      const res = await fetchCounterpartyGraph(item.iinBin, 2, 6)
      setInvestigationModal((prev) => ({
        ...prev,
        loading: false,
        error: '',
        nodes: res.nodes || [],
        edges: res.edges || [],
      }))
    } catch (e) {
      setInvestigationModal((prev) => ({
        ...prev,
        loading: false,
        error: e?.message || 'Не удалось загрузить граф связей',
      }))
    }
  }, [])

  const closeCashModal = () => {
    setCashModal((prev) => ({ ...prev, open: false }))
  }
  const toggleCashSort = (field) => {
    setCashTxSort((prev) => {
      if (prev.field === field) {
        return { field, direction: prev.direction === 'desc' ? 'asc' : 'desc' }
      }
      return { field, direction: 'desc' }
    })
  }
  const closeCategoryModal = () => {
    setCategoryModal((prev) => ({ ...prev, open: false }))
  }
  const toggleCategorySort = (field) => {
    setCategoryTxSort((prev) => {
      if (prev.field === field) {
        return { field, direction: prev.direction === 'desc' ? 'asc' : 'desc' }
      }
      return { field, direction: 'desc' }
    })
  }
  const closeInvestigationModal = () => {
    setInvestigationModal((prev) => ({ ...prev, open: false }))
  }
  const zoomInvestigationIn = () => setInvestigationZoom((prev) => Math.min(2.5, prev * 1.12))
  const zoomInvestigationOut = () => setInvestigationZoom((prev) => Math.max(0.35, prev * 0.88))
  const resetInvestigationZoom = () => setInvestigationZoom(1)
  const getTouchDistance = (touches) => {
    if (!touches || touches.length < 2) return null
    const a = touches[0]
    const b = touches[1]
    return Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY)
  }

  const handleInvestigationTouchStart = (e) => {
    if (e.touches.length < 2) return
    const distance = getTouchDistance(e.touches)
    if (!distance) return
    pinchStartDistanceRef.current = distance
    pinchStartZoomRef.current = investigationZoom
  }

  const handleInvestigationTouchMove = (e) => {
    if (e.touches.length < 2) return
    const start = pinchStartDistanceRef.current
    if (!start) return
    const current = getTouchDistance(e.touches)
    if (!current) return
    e.preventDefault()
    e.stopPropagation()
    const next = pinchStartZoomRef.current * (current / start)
    setInvestigationZoom(Math.max(0.35, Math.min(2.5, next)))
  }

  const handleInvestigationTouchEnd = () => {
    pinchStartDistanceRef.current = null
  }

  useEffect(() => {
    const el = investigationViewportRef.current
    if (!el || !investigationModal.open) return

    const onWheel = (e) => {
      if (!e.ctrlKey) return
      e.preventDefault()
      e.stopPropagation()
      const next = e.deltaY < 0 ? investigationZoom * 1.08 : investigationZoom * 0.92
      setInvestigationZoom(Math.max(0.35, Math.min(2.5, next)))
    }

    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [investigationModal.open, investigationZoom])

  useEffect(() => {
    let cancelled = false

    ;(async () => {
      try {
        await loadTimeSeries(timePeriod)
        if (cancelled) return
        await loadSummary()
        if (cancelled) return
        await loadExpenses(bottomToggle)
        if (cancelled) return
        await loadCounterparties()
        if (cancelled) return
        await loadCashPanels()
        if (cancelled) return
        await loadCategorySummary()
      } finally {
        if (!cancelled) setAnalyticsBootstrapped(true)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [
    bottomToggle,
    loadCashPanels,
    loadCategorySummary,
    loadCounterparties,
    loadExpenses,
    loadSummary,
    loadTimeSeries,
    timePeriod,
  ])

  const CardClass = 'bento-tile p-6'
  const headingText = 'text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-500'
  const subtitleText = 'text-[8px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-600'
  const mutedText = 'text-[8px] font-bold text-slate-400 dark:text-zinc-600'
  const controlShellClass = 'bg-slate-50/50 dark:bg-zinc-900/50 border border-slate-100 dark:border-zinc-800 rounded-lg p-0.5'
  const actionButtonClass = 'bg-slate-50 dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-lg text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-zinc-400 hover:text-indigo-500 hover:border-indigo-500/30 transition-all'
  const modalClass = isDark
    ? 'bg-slate-950 border-zinc-800 shadow-[0_0_0_1px_rgba(255,255,255,0.05),0_20px_50px_rgba(0,0,0,0.5)]'
    : 'bg-white border-slate-200 shadow-[0_20px_50px_rgba(0,0,0,0.1)]'
  const modalHeaderBorderClass = isDark ? 'border-zinc-800' : 'border-slate-100'
  const tableHeaderClass = isDark ? 'text-zinc-500 border-zinc-800' : 'text-slate-400 border-slate-100'
  const tableRowClass = isDark ? 'border-zinc-900/50 text-zinc-100' : 'border-slate-50 text-slate-800'
  const tableTextClass = isDark ? 'text-zinc-400' : 'text-slate-600'

  const toggleBtnClass = (active) =>
    `px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${
      active
        ? isDark
          ? 'bg-cyan-400/14 text-cyan-100 ring-1 ring-cyan-400/30 shadow-[0_0_18px_rgba(34,211,238,0.16)]'
          : 'bg-cyan-100 text-cyan-900 ring-1 ring-cyan-300 shadow-[0_0_16px_rgba(34,211,238,0.12)]'
        : isDark
          ? 'text-slate-400 hover:text-cyan-100 hover:bg-slate-800'
          : 'text-slate-500 hover:text-cyan-900 hover:bg-cyan-50'
    }`

  const expenseList = (expenseData.data || []).map((d) => ({
    name: compactLabel(d.counterparty?.name || '—'),
    iinBin: d.counterparty?.iin_bin || '',
    account: d.counterparty?.account || '',
    amount: d.amount,
  }))

  const cpList = mergeAgentRows(counterparties.map((d) => ({
    name: d.counterparty?.name || '—',
    iinBin: d.counterparty?.iin_bin || '',
    account: d.counterparty?.account || '',
    turnover: d.total_turnover,
    txCount: d.transaction_count,
  })), 'turnover').map((item, i) => ({
    ...item,
    color: DONUT_COLORS[i % DONUT_COLORS.length],
  }))

  const cashWithdrawalList = mergeAgentRows((cashWithdrawals.data || []).map((d) => ({
    name: d.counterparty?.name || '—',
    iinBin: d.counterparty?.iin_bin || '',
    account: d.counterparty?.account || '',
    amount: d.amount || 0,
    txCount: d.transaction_count || 0,
    lastDate: d.last_transaction_date || '',
  })), 'amount').map((item, i) => ({
    ...item,
    color: CASH_WITHDRAWAL_COLORS[i % CASH_WITHDRAWAL_COLORS.length],
  }))

  const cashDepositList = mergeAgentRows((cashDeposits.data || []).map((d) => ({
    name: d.counterparty?.name || '—',
    iinBin: d.counterparty?.iin_bin || '',
    account: d.counterparty?.account || '',
    amount: d.amount || 0,
    txCount: d.transaction_count || 0,
    lastDate: d.last_transaction_date || '',
  })), 'amount').map((item, i) => ({
    ...item,
    color: CASH_DEPOSIT_COLORS[i % CASH_DEPOSIT_COLORS.length],
  }))

  const rawCategoryBars = (categorySummary || []).slice(0, 16).map((item) => ({
    name: item.category,
    txCount: item.transaction_count || 0,
    turnover: item.total_turnover || 0,
    totalDebit: item.total_debit || 0,
    totalCredit: item.total_credit || 0,
  }))
  const sortedCategoryBars = [...rawCategoryBars].sort((a, b) => Number(b.turnover || 0) - Number(a.turnover || 0))
  const categoryPalette = sortedCategoryBars.map((_, idx) => (
    CATEGORY_MUTED_COLORS[idx % CATEGORY_MUTED_COLORS.length]
  ))
  const categoryBars = sortedCategoryBars.map((item, idx) => ({
    ...item,
    color: categoryPalette[idx] || '#22bdee',
  }))

  const tooltipStyle = {
    backgroundColor: isDark ? '#1f2937' : '#ffffff',
    border: `1px solid ${isDark ? '#374151' : '#e5e7eb'}`,
    borderRadius: '8px',
    color: isDark ? '#f3f4f6' : '#111827',
    fontSize: '12px',
  }

  const axisColor = isDark ? '#6b7280' : '#9ca3af'
  const categoryAxisColor = isDark ? '#cbd5e1' : '#334155'
  const chartMaxValue = chartData.reduce((acc, point) => {
    const maxPoint = Math.max(Number(point?.credit || 0), Number(point?.debit || 0))
    return Math.max(acc, maxPoint)
  }, 0)
  const zoomedYAxisMax = chartMaxValue > 0 ? Math.max(1, chartMaxValue / chartZoom) : 1
  const categoryMaxValue = categoryBars.reduce((acc, item) => Math.max(acc, Number(item?.turnover || 0)), 0)
  const zoomedCategoryMax = categoryMaxValue > 0 ? Math.max(1, categoryMaxValue / categoryZoom) : 1
  const categoryRows = []
  for (let i = 0; i < categoryBars.length; i += 7) {
    categoryRows.push(categoryBars.slice(i, i + 7))
  }
  const renderCategoryTick = ({ x, y, payload }) => {
    const lines = splitLabelLines(payload?.value || '', 14)
    return (
      <text
        x={x}
        y={y + 12}
        textAnchor="middle"
        fill={categoryAxisColor}
        fontSize={13}
        className="cursor-pointer select-none"
        onClick={() => openCategoryTransactions(payload?.value)}
      >
        {lines.map((line, idx) => (
          <tspan key={`${payload?.value}-${idx}`} x={x} dy={idx === 0 ? 0 : 14}>
            {line}
          </tspan>
        ))}
      </text>
    )
  }
  const graphNodePositions = buildGraphLayout(investigationModal.nodes, 900, 520)
  const sortedCategoryModalRows = [...(categoryModal.rows || [])].sort((a, b) => {
    const dir = categoryTxSort.direction === 'asc' ? 1 : -1
    if (categoryTxSort.field === 'date') {
      const toTs = (value) => {
        const m = String(value || '').match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{2}):(\d{2}))?/)
        if (!m) return 0
        const [, dd, mm, yyyy, hh = '00', min = '00'] = m
        return new Date(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(min)).getTime()
      }
      return (toTs(a?.date) - toTs(b?.date)) * dir
    }
    return (Number(a?.amount_tenge || 0) - Number(b?.amount_tenge || 0)) * dir
  })
  const exportCategoryModal = async (format) => {
    const rows = sortedCategoryModalRows
    const title = categoryModal.title || 'Транзакции категории'
    const fileBase = safeExportFileName(title)

    if (format === 'excel') {
      const XLSX = await import('xlsx')
      const exportRows = buildCategoryExportRows(rows)
      const worksheet = XLSX.utils.json_to_sheet(exportRows)
      autoFitWorksheetColumns(worksheet, exportRows)
      const workbook = XLSX.utils.book_new()
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Transactions')
      XLSX.writeFile(workbook, `${fileBase}.xlsx`)
      return
    }

    const html = buildCategoryExportHtml(title, rows)
    if (format === 'word') {
      downloadExportBlob(`\ufeff${html}`, `${fileBase}.doc`, 'application/msword;charset=utf-8')
      return
    }

    const printWindow = window.open('', '_blank')
    if (!printWindow) {
      downloadExportBlob(`\ufeff${html}`, `${fileBase}.html`, 'text/html;charset=utf-8')
      return
    }
    printWindow.document.open()
    printWindow.document.write(html)
    printWindow.document.close()
    printWindow.focus()
    printWindow.print()
  }
  const sortedCashModalRows = [...(cashModal.rows || [])].sort((a, b) => {
    const dir = cashTxSort.direction === 'asc' ? 1 : -1
    if (cashTxSort.field === 'date') {
      const toTs = (value) => {
        const m = String(value || '').match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{2}):(\d{2}))?/)
        if (!m) return 0
        const [, dd, mm, yyyy, hh = '00', min = '00'] = m
        return new Date(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(min)).getTime()
      }
      return (toTs(a?.date) - toTs(b?.date)) * dir
    }
    return (Number(a?.amount_tenge || 0) - Number(b?.amount_tenge || 0)) * dir
  })
  const exportCashModalExcel = async () => {
    const XLSX = await import('xlsx')
    const exportRows = buildTransactionExportRows(sortedCashModalRows)
    const worksheet = XLSX.utils.json_to_sheet(exportRows)
    autoFitWorksheetColumns(worksheet, exportRows)
    const workbook = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Transactions')
    XLSX.writeFile(workbook, `${safeExportFileName(`${cashModal.title || 'transactions'}-transactions`)}.xlsx`)
  }
  const renderTimeDot = useCallback((color) => (props) => {
    const { cx, cy, payload } = props || {}
    if (typeof cx !== 'number' || typeof cy !== 'number') return null
    return (
      <g style={{ cursor: 'pointer' }} onMouseDown={() => openTimePointTransactions(payload)}>
        <circle
          cx={cx}
          cy={cy}
          r={10}
          fill="transparent"
          stroke="transparent"
          style={{ pointerEvents: 'all' }}
        />
        <circle
          cx={cx}
          cy={cy}
          r={3.5}
          fill={color}
          stroke={isDark ? '#e5e7eb' : '#111827'}
          strokeWidth={1}
          style={{ pointerEvents: 'none' }}
        />
      </g>
    )
  }, [isDark, openTimePointTransactions])
  const handleTimeChartClick = useCallback((state) => {
    const payload =
      state?.activePayload?.[0]?.payload
      || state?.payload
      || (state?.activeLabel ? chartData.find((p) => p.label === state.activeLabel || p.date === state.activeLabel) : null)
    if (!payload?.date) return
    openTimePointTransactions(payload)
  }, [openTimePointTransactions, chartData])
  const RenderActiveExpenseBar = useCallback((props) => (
    <Rectangle
      {...props}
      radius={[0, 4, 4, 0]}
      fill={props.fill}
      stroke={isDark ? 'rgba(255,255,255,0.42)' : 'rgba(15,23,42,0.18)'}
      strokeWidth={1.25}
      style={{
        filter: isDark
          ? 'drop-shadow(0 0 10px rgba(255,255,255,0.10))'
          : 'drop-shadow(0 0 8px rgba(15,23,42,0.08))',
      }}
    />
  ), [isDark])

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto pb-12">
      {/* SECTION 1 + 2: KPIs + Time Series + Top Expenses */}
      <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_320px] gap-6">
        <div className="space-y-6">
          <div ref={kpiGridRef} className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bento-tile p-5 flex min-w-0 flex-col justify-between h-28 overflow-hidden">
          <div className="flex items-center justify-between">
            <span className={headingText}>Поступления</span>
            <div className="w-7 h-7 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
              <ArrowUpRight className="w-4 h-4" />
            </div>
          </div>
          <div className="flex min-w-0 max-w-full items-baseline gap-1.5 overflow-hidden text-emerald-600 dark:text-emerald-400">
            <span className="min-w-0 whitespace-nowrap font-black leading-none tabular-nums" style={{ fontSize: kpiValueFontSize }}>
              {fmtFull(kpi.total_credit)}
            </span>
            <span className="shrink-0 text-sm font-bold opacity-60 uppercase leading-none">{TENGE}</span>
          </div>
        </div>

        <div className="bento-tile p-5 flex min-w-0 flex-col justify-between h-28 overflow-hidden">
          <div className="flex items-center justify-between">
            <span className={headingText}>Транзакции</span>
            <div className="w-7 h-7 rounded-lg bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="flex min-w-0 max-w-full items-baseline gap-1.5 overflow-hidden">
            <span className="min-w-0 whitespace-nowrap font-black text-slate-900 dark:text-zinc-100 leading-none tabular-nums" style={{ fontSize: kpiValueFontSize }}>
              {kpi.total_transactions.toLocaleString()}
            </span>
            <span className="shrink-0 text-sm font-bold text-slate-400 uppercase leading-none">ЕД.</span>
          </div>
        </div>

        <div className="bento-tile p-5 flex min-w-0 flex-col justify-between h-28 overflow-hidden">
          <div className="flex items-center justify-between">
            <span className={headingText}>Расход</span>
            <div className="w-7 h-7 rounded-lg bg-rose-50 dark:bg-rose-900/20 text-rose-500 dark:text-rose-400 flex items-center justify-center">
              <ArrowDownRight className="w-4 h-4" />
            </div>
          </div>
          <div className="flex min-w-0 max-w-full items-baseline gap-1.5 overflow-hidden text-rose-500">
            <span className="min-w-0 whitespace-nowrap font-black leading-none tabular-nums" style={{ fontSize: kpiValueFontSize }}>−{fmtFull(kpi.total_debit)}</span>
            <span className="shrink-0 text-sm font-bold opacity-60 uppercase leading-none">{TENGE}</span>
          </div>
        </div>

        <div className="bento-tile p-5 flex min-w-0 flex-col justify-between h-28 overflow-hidden">
          <div className="flex items-center justify-between">
            <span className={headingText}>Общий Оборот</span>
            <div className="w-7 h-7 rounded-lg bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400 flex items-center justify-center">
              <Database className="w-4 h-4" />
            </div>
          </div>
          <div className="flex min-w-0 max-w-full items-baseline gap-1.5 overflow-hidden text-slate-900 dark:text-zinc-100">
            <span className="min-w-0 whitespace-nowrap font-black leading-none tabular-nums" style={{ fontSize: kpiValueFontSize }}>
              {fmtFull(kpi.total_turnover)}
            </span>
            <span className="shrink-0 text-sm font-bold text-slate-400 uppercase leading-none">{TENGE}</span>
          </div>
        </div>
          </div>

        {/* TIME SERIES */}
        <div className="bento-tile p-6 flex flex-col h-[520px]">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">
                <Filter className="w-4 h-4" />
              </div>
              <h2 className={headingText}>График транзакций</h2>
            </div>
            <div className="flex items-center gap-2">
              <div className={`flex items-center gap-1 p-1 rounded-lg ${controlShellClass}`}>
                {['Год', 'Месяц', 'День'].map((period) => (
                  <button key={period} onClick={() => setTimePeriod(period)} className={toggleBtnClass(timePeriod === period)}>
                    {period}
                  </button>
                ))}
              </div>
              <button
                onClick={() => setChartZoom(1)}
                className="p-1 px-3 bg-slate-50 dark:bg-zinc-900 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded-lg text-slate-400 transition-all text-[9px] font-black uppercase"
              >
                Reset
              </button>
            </div>
          </div>

          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={chartData}
                margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
                onClick={handleTimeChartClick}
                style={{ cursor: 'pointer' }}
              >
                <defs>
                  <linearGradient id="gradCredit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradDebit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#27272a' : '#f1f5f9'} vertical={false} />
                <XAxis dataKey="label" tick={{ fill: axisColor, fontSize: 11 }} axisLine={{ stroke: axisColor }} tickLine={false} />
                <YAxis
                  domain={[0, zoomedYAxisMax]}
                  allowDataOverflow
                  tickFormatter={fmt}
                  tick={{ fill: axisColor, fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  width={50}
                />
                <Tooltip
                  contentStyle={tooltipStyle}
                  formatter={(value, name) => [
                    `${fmtFull(value)} ${TENGE}`,
                    name === 'credit' ? 'Поступления' : 'Расходы',
                  ]}
                />
                <Area type="monotone" dataKey="credit" stroke="#34d399" strokeWidth={2} fill="url(#gradCredit)" dot={renderTimeDot('#34d399')} activeDot={{ r: 5 }} />
                <Area type="monotone" dataKey="debit" stroke="#f87171" strokeWidth={2} fill="url(#gradDebit)" dot={renderTimeDot('#f87171')} activeDot={{ r: 5 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          
          <div className="mt-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#10b981]"></div>
                <span className={subtitleText}>Поступления</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#ef4444]"></div>
                <span className={subtitleText}>Расходы</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
               <span className={mutedText}>Масштаб {chartZoom}x</span>
               <input
                 type="range"
                 min="1"
                 max="100"
                 step="1"
                 value={chartZoom}
                 onChange={(e) => setChartZoom(Number(e.target.value))}
                 className="w-24 h-1 bg-slate-200 dark:bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-indigo-600"
               />
            </div>
          </div>
        </div>
      </div>

        {/* SIDEBAR: TOP EXPENSES */}
        <div className="bento-tile p-6 flex flex-col h-[656px]">
          <div className="mb-7">
            <h3 className={headingText}>
              {bottomToggle === 'Расходы' ? 'Топ Расходов' : 'Топ Доходов'}
            </h3>
          </div>

          <div className="flex-1 min-h-0 flex flex-col">
            <div className="h-[220px] shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={expenseList.slice(0, 8)} layout="vertical" margin={{ top: 0, right: 8, left: -22, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={10}
                  tick={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={tooltipStyle}
                  itemStyle={{ color: isDark ? '#ffffff' : '#111827' }}
                  labelStyle={{ color: isDark ? '#ffffff' : '#111827' }}
                  formatter={(value) => [`${fmtFull(value)} ${TENGE}`, bottomToggle === 'Расходы' ? 'Расход' : 'Доход']}
                />
                <Bar 
                  dataKey="amount" 
                  radius={[0, 6, 6, 0]} 
                  barSize={22} 
                  onClick={(data) => openTopExpenseTransactions(data?.payload)} 
                  style={{ cursor: 'pointer' }}
                >
                  {expenseList.slice(0, 8).map((entry, i) => (
                    <Cell 
                      key={i} 
                      fill={bottomToggle === 'Расходы' ? '#ef4444' : '#10b981'} 
                      fillOpacity={0.82 - i * 0.08} 
                    />
                  ))}
                </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            
            <div className="mt-6 space-y-2.5">
              {expenseList.slice(0, 5).map((item, i) => (
                <div key={i} className="flex items-center justify-between gap-3 border-b border-slate-200/80 pb-2 last:border-b-0 last:pb-0 dark:border-zinc-800/80">
                  <span className={`truncate text-[11px] font-bold ${isDark ? 'text-zinc-300' : 'text-slate-600'}`}>
                    {item.name}
                  </span>
                  <span className={`text-[10px] font-black font-mono ${bottomToggle === 'Расходы' ? 'text-rose-500' : 'text-emerald-500'}`}>
                    {fmt(item.amount)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-auto rounded-[26px] border border-slate-200 bg-slate-50/90 p-4 dark:border-zinc-800 dark:bg-zinc-950/40">
            <div className={`mb-4 flex items-center gap-1 rounded-2xl p-1 ${controlShellClass}`}>
              {['Расходы', 'Поступления'].map((opt) => (
                <button key={opt} onClick={() => setBottomToggle(opt)} className={`flex-1 ${toggleBtnClass(bottomToggle === opt)}`}>
                  {opt}
                </button>
              ))}
            </div>
            <div className="mt-4 border-t border-slate-200 pt-4 dark:border-zinc-800">
               <p className={subtitleText}>ИТОГО {bottomToggle.toUpperCase()}</p>
               <p className="mt-1 text-[28px] font-black leading-none tracking-tight text-slate-900 dark:text-zinc-100">{fmtFull(expenseData.total)} <span className="text-base text-slate-400 dark:text-zinc-500">{TENGE}</span></p>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 3: CATEGORIES */}
      <section className="bento-tile p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <ListTodo className="w-4 h-4 text-indigo-500" />
            <h3 className={headingText}>Анализ категорий</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className={mutedText}>Zoom {categoryZoom}x</span>
            <input
              type="range"
              min="1"
              max="100"
              step="1"
              value={categoryZoom}
              onChange={(e) => setCategoryZoom(Number(e.target.value))}
              className="w-20 h-1 accent-indigo-500"
            />
          </div>
        </div>

        {categoryBars.length === 0 ? (
          <div className={`text-xs ${subtitleText}`}>Нет данных по категориям</div>
        ) : (
          <div className="space-y-6">
            {categoryRows.map((row, rowIdx) => (
              <div key={`cat-row-${rowIdx}`} style={{ width: '100%', height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={row} margin={{ top: 6, right: 10, left: 0, bottom: 24 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#374151' : '#e5e7eb'} vertical={false} />
                    <XAxis
                      dataKey="name"
                      tick={renderCategoryTick}
                      axisLine={false}
                      tickLine={false}
                      angle={0}
                      textAnchor="middle"
                      interval={0}
                      height={86}
                    />
                    <YAxis
                      domain={[0, zoomedCategoryMax]}
                      allowDataOverflow
                      tickFormatter={fmt}
                      tick={{ fill: axisColor, fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                      width={50}
                    />
                    <Tooltip
                      contentStyle={tooltipStyle}
                      cursor={false}
                      itemStyle={{ color: isDark ? '#f3f4f6' : '#111827' }}
                      labelStyle={{ color: isDark ? '#f3f4f6' : '#111827' }}
                      formatter={(value, name) => {
                        if (name === 'turnover') return [`${fmtFull(value)} ${TENGE}`, 'Оборот']
                        return [value, 'Транзакций']
                      }}
                    />
                    <Bar
                      dataKey="turnover"
                      radius={[4, 4, 0, 0]}
                      barSize={40}
                      activeBar={{ fill: '#67e8f9' }}
                    >
                      {row.map((cat) => (
                        <Cell
                          key={cat.name}
                          fill={cat.color}
                          cursor="pointer"
                          onClick={() => openCategoryTransactions(cat.name)}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* SECTION 4: COUNTERPARTIES & CASH */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-2 lg:items-stretch">
        <div className="bento-tile flex h-full min-h-[400px] flex-col p-6">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 rounded-xl bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">
              <Database className="w-4 h-4" />
            </div>
            <h2 className={headingText}>Топ контрагентов</h2>
          </div>

          <div className="flex-1 flex flex-col lg:flex-row items-center gap-6 min-h-0">
            <div className="w-full lg:w-1/2 h-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={cpList} dataKey="turnover" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} stroke="none">
                    {cpList.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={tooltipStyle}
                    itemStyle={{ color: isDark ? '#f3f4f6' : '#111827' }}
                    labelStyle={{ color: isDark ? '#f3f4f6' : '#111827' }}
                    formatter={(value) => [`${fmtFull(value)} ${TENGE}`, 'Оборот']}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="w-full lg:w-1/2 overflow-y-auto custom-scrollbar pr-1 max-h-full space-y-2.5">
              {cpList.map((cp, i) => (
                <div key={i} className="flex items-center justify-between gap-2 p-1.5 rounded-lg hover:bg-slate-50 dark:hover:bg-zinc-900 transition-colors">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: cp.color }}></span>
                    <button
                      type="button"
                      onClick={() => openInvestigationGraph(cp)}
                      className={`text-[10px] font-bold truncate text-left transition-colors ${
                        isDark ? 'text-zinc-300 hover:text-white' : 'text-slate-700 hover:text-indigo-600'
                      }`}
                      title="Режим расследования"
                    >
                      {cp.name}
                    </button>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-[10px] font-black text-slate-900 dark:text-zinc-100 font-mono">{fmt(cp.turnover)}</span>
                    <button
                      type="button"
                      onClick={() => openCounterpartyTransactions(cp)}
                      className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-zinc-800 text-[8px] font-black text-slate-500 hover:text-indigo-500 transition-colors"
                    >
                      {cp.txCount}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex h-full flex-col gap-4">
          <DonutWithList
            title={cashToggle === 'withdrawal' ? 'Снятие наличных' : 'Пополнение наличными'}
            iconType={cashToggle}
            data={cashToggle === 'withdrawal' ? cashWithdrawalList : cashDepositList}
            total={(cashToggle === 'withdrawal' ? cashWithdrawals.total : cashDeposits.total) || 0}
            isDark={isDark}
            headingText={headingText}
            subtitleText={subtitleText}
            mutedText={mutedText}
            tooltipStyle={tooltipStyle}
            onTxClick={(item) => openCashTransactions(cashToggle, item)}
            onToggle={() => setCashToggle(cashToggle === 'withdrawal' ? 'deposit' : 'withdrawal')}
          />
        </div>
      </section>

      {investigationModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={closeInvestigationModal}></div>
          <div className={`relative z-10 w-full max-w-6xl max-h-[88vh] overflow-hidden rounded-xl border ${modalClass}`}>
            <div className={`px-5 py-4 border-b flex items-center justify-between ${modalHeaderBorderClass}`}>
              <div>
                <h3 className={`text-base font-semibold ${headingText}`}>Режим расследования</h3>
                <p className={`text-xs ${subtitleText}`}>Центр: {investigationModal.centerName}</p>
              </div>
              <button
                type="button"
                onClick={closeInvestigationModal}
                className={`px-3 py-1.5 rounded-md text-xs ${actionButtonClass}`}
              >
                Закрыть
              </button>
            </div>

            <div className="p-4 overflow-auto max-h-[72vh]">
              {investigationModal.loading && <div className={`text-sm ${subtitleText}`}>Загрузка графа...</div>}
              {!investigationModal.loading && investigationModal.error && (
                <div className="text-sm text-red-400">{investigationModal.error}</div>
              )}
              {!investigationModal.loading && !investigationModal.error && investigationModal.nodes.length === 0 && (
                <div className={`text-sm ${subtitleText}`}>Нет связей для отображения</div>
              )}
              {!investigationModal.loading && !investigationModal.error && investigationModal.nodes.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={zoomInvestigationOut}
                      className={`px-2 py-1 rounded text-xs ${actionButtonClass}`}
                    >
                      -
                    </button>
                    <button
                      type="button"
                      onClick={zoomInvestigationIn}
                      className={`px-2 py-1 rounded text-xs ${actionButtonClass}`}
                    >
                      +
                    </button>
                    <button
                      type="button"
                      onClick={resetInvestigationZoom}
                      className={`px-2 py-1 rounded text-xs ${actionButtonClass}`}
                    >
                      100%
                    </button>
                    <span className={`text-xs ${subtitleText}`}>Масштаб: {investigationZoom.toFixed(2)}x</span>
                  </div>
                  <div
                    ref={investigationViewportRef}
                    className={`rounded-3xl border overflow-auto backdrop-blur-xl ${isDark ? 'border-white/10 bg-white/[0.05]' : 'border-white/55 bg-white/[0.40]'}`}
                  >
                    <svg
                      viewBox="0 0 900 520"
                      className="w-full min-w-[900px]"
                      onTouchStart={handleInvestigationTouchStart}
                      onTouchMove={handleInvestigationTouchMove}
                      onTouchEnd={handleInvestigationTouchEnd}
                      style={{ touchAction: 'none' }}
                    >
                      <g transform={`translate(450 260) scale(${investigationZoom}) translate(-450 -260)`}>
                        {investigationModal.edges.map((edge, idx) => {
                          const from = graphNodePositions[edge.source]
                          const to = graphNodePositions[edge.target]
                          if (!from || !to) return null
                          const strokeWidth = Math.max(2.2, Math.min(8, 2.2 + Math.log10((edge.amount || 1) + 1) * 1.15))
                          return (
                            <g key={`edge-${idx}`}>
                              <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke={isDark ? '#475569' : '#94a3b8'} strokeOpacity="0.7" strokeWidth={strokeWidth} />
                            </g>
                          )
                        })}

                        {investigationModal.nodes.map((node) => {
                          const p = graphNodePositions[node.id]
                          if (!p) return null
                          const color = node.level === 0 ? '#54d6d0' : node.level === 1 ? '#5b9dff' : '#9278f5'
                          const ringWidth = Math.max(4, p.r * 0.42)
                          const innerRadius = Math.max(1, p.r - ringWidth / 2)
                          const innerFill = isDark ? '#020617' : '#f8fafc'
                          const labelY = p.y + p.r + ringWidth / 2 + 14
                          return (
                            <g
                              key={node.id}
                              onClick={() => openInvestigationGraph({ iinBin: node.id, name: node.label })}
                              className="cursor-pointer"
                            >
                              <circle
                                cx={p.x}
                                cy={p.y}
                                r={p.r}
                                fill="none"
                                stroke={color}
                                strokeWidth={ringWidth}
                                strokeOpacity="0.92"
                              />
                              <circle
                                cx={p.x}
                                cy={p.y}
                                r={innerRadius}
                                fill={innerFill}
                              />
                              <circle
                                cx={p.x}
                                cy={p.y}
                                r={p.r + ringWidth / 2 + 0.5}
                                fill="none"
                                stroke={isDark ? '#cbd5e1' : '#64748b'}
                                strokeWidth="1"
                                strokeOpacity="0.75"
                              />
                              <text x={p.x} y={labelY} textAnchor="middle" className={isDark ? 'fill-gray-200' : 'fill-gray-700'} fontSize="11">
                                {splitLabelLines(node.label, 26).map((line, idx) => (
                                  <tspan key={`${node.id}-line-${idx}`} x={p.x} dy={idx === 0 ? 0 : 12}>
                                    {line}
                                  </tspan>
                                ))}
                              </text>
                            </g>
                          )
                        })}
                      </g>
                    </svg>
                  </div>
                  <div className={`text-xs ${subtitleText}`}>
                    Уровни: центр (желтый), прямые связи (синий), второй уровень цепочки (фиолетовый).
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {cashModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={closeCashModal}></div>
          <div className={`relative z-10 w-full max-w-5xl max-h-[85vh] overflow-hidden rounded-xl border ${modalClass}`}>
            <div className={`px-5 py-4 border-b flex items-center justify-between ${modalHeaderBorderClass}`}>
              <div>
                <h3 className={`text-base font-semibold ${headingText}`}>{cashModal.title} - транзакции</h3>
                <p className={`text-xs ${subtitleText}`}>Найдено: {cashModal.total}</p>
              </div>
              <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={exportCashModalExcel}
                disabled={cashModal.loading || cashModal.rows.length === 0}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-black uppercase tracking-widest transition-all disabled:opacity-40 ${
                  isDark
                    ? 'border border-emerald-300/25 bg-emerald-300/10 text-emerald-100 hover:bg-emerald-300/16 hover:border-emerald-300/40'
                    : 'border border-emerald-200 bg-emerald-50 text-emerald-800 hover:bg-emerald-100'
                }`}
              >
                <FileSpreadsheet className="h-3.5 w-3.5" />
                Excel
              </button>
              <button
                type="button"
                onClick={closeCashModal}
                className={`px-3 py-1.5 rounded-md text-xs ${actionButtonClass}`}
              >
                Закрыть
              </button>
              </div>
            </div>

            <div className="p-4 overflow-auto max-h-[65vh]">
              {cashModal.loading && <div className={`text-sm ${subtitleText}`}>Загрузка...</div>}
              {!cashModal.loading && cashModal.error && <div className="text-sm text-red-400">{cashModal.error}</div>}
              {!cashModal.loading && !cashModal.error && cashModal.rows.length === 0 && (
                <div className={`text-sm ${subtitleText}`}>Нет транзакций</div>
              )}
              {!cashModal.loading && !cashModal.error && cashModal.rows.length > 0 && (
                <table className="w-full text-xs">
                  <thead>
                    <tr className={`${tableHeaderClass} border-b`}>
                      <th className="text-left py-2 pr-3">
                        <button
                          type="button"
                          onClick={() => toggleCashSort('date')}
                          className={`inline-flex items-center gap-1 transition-colors ${isDark ? 'hover:text-cyan-50' : 'hover:text-cyan-900'}`}
                        >
                          Дата
                          {cashTxSort.field === 'date' ? (cashTxSort.direction === 'desc' ? '↓' : '↑') : ''}
                        </button>
                      </th>
                      <th className="text-left py-2 pr-3">Отправитель</th>
                      <th className="text-left py-2 pr-3">Получатель</th>
                      <th className="text-left py-2 pr-3">Назначение</th>
                      <th className="text-right py-2 pr-3">
                        <button
                          type="button"
                          onClick={() => toggleCashSort('amount_tenge')}
                          className={`inline-flex items-center gap-1 transition-colors ${isDark ? 'hover:text-cyan-50' : 'hover:text-cyan-900'}`}
                        >
                          Сумма
                          {cashTxSort.field === 'amount_tenge' ? (cashTxSort.direction === 'desc' ? '↓' : '↑') : ''}
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedCashModalRows.map((tx) => (
                      <tr key={tx.id} className={`${tableRowClass} border-b`}>
                        <td className="py-2 pr-3 whitespace-nowrap">{tx.date}</td>
                        <td className="py-2 pr-3">{tx.sender_name || '—'}</td>
                        <td className="py-2 pr-3">{tx.recipient_name || '—'}</td>
                        <td className={`py-2 pr-3 ${tableTextClass}`}>{tx.purpose || '—'}</td>
                        <td className="py-2 pr-3 text-right font-mono whitespace-nowrap">{fmtFull(tx.amount_tenge)} {TENGE}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {categoryModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={closeCategoryModal}></div>
          <div className={`relative z-10 w-full max-w-6xl max-h-[85vh] overflow-hidden rounded-xl border ${modalClass}`}>
            <div className={`px-5 py-4 border-b flex items-center justify-between ${modalHeaderBorderClass}`}>
              <div>
                <h3 className={`text-base font-semibold ${headingText}`}>{categoryModal.title}</h3>
                <p className={`text-xs ${subtitleText}`}>Найдено: {categoryModal.total}</p>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => exportCategoryModal('excel')}
                  disabled={categoryModal.loading || categoryModal.rows.length === 0}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs disabled:opacity-40 ${actionButtonClass}`}
                >
                  <FileSpreadsheet className="h-3.5 w-3.5" />
                  Excel
                </button>
                <button
                  type="button"
                  onClick={() => exportCategoryModal('pdf')}
                  disabled={categoryModal.loading || categoryModal.rows.length === 0}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs disabled:opacity-40 ${actionButtonClass}`}
                >
                  <Printer className="h-3.5 w-3.5" />
                  PDF
                </button>
                <button
                  type="button"
                  onClick={() => exportCategoryModal('word')}
                  disabled={categoryModal.loading || categoryModal.rows.length === 0}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs disabled:opacity-40 ${actionButtonClass}`}
                >
                  <FileText className="h-3.5 w-3.5" />
                  Word
                </button>
                <button
                  type="button"
                  onClick={closeCategoryModal}
                  className={`px-3 py-1.5 rounded-md text-xs ${actionButtonClass}`}
                >
                  Закрыть
                </button>
              </div>
            </div>

            <div className="p-4 overflow-auto max-h-[65vh]">
              {categoryModal.loading && <div className={`text-sm ${subtitleText}`}>Загрузка...</div>}
              {!categoryModal.loading && categoryModal.error && <div className="text-sm text-red-400">{categoryModal.error}</div>}
              {!categoryModal.loading && !categoryModal.error && categoryModal.rows.length === 0 && (
                <div className={`text-sm ${subtitleText}`}>Нет транзакций</div>
              )}
              {!categoryModal.loading && !categoryModal.error && categoryModal.rows.length > 0 && (
                <table className="w-full text-xs">
                  <thead>
                    <tr className={`${tableHeaderClass} border-b`}>
                      <th className="text-left py-2 pr-3">
                        <button
                          type="button"
                          onClick={() => toggleCategorySort('date')}
                          className={`inline-flex items-center gap-1 transition-colors ${isDark ? 'hover:text-cyan-50' : 'hover:text-cyan-900'}`}
                        >
                          Дата
                          {categoryTxSort.field === 'date' ? (categoryTxSort.direction === 'desc' ? '↓' : '↑') : ''}
                        </button>
                      </th>
                      <th className="text-left py-2 pr-3">Отправитель</th>
                      <th className="text-left py-2 pr-3">Получатель</th>
                      <th className="text-left py-2 pr-3">Назначение</th>
                      <th className="text-right py-2 pr-3">
                        <button
                          type="button"
                          onClick={() => toggleCategorySort('amount_tenge')}
                          className={`inline-flex items-center gap-1 transition-colors ${isDark ? 'hover:text-cyan-50' : 'hover:text-cyan-900'}`}
                        >
                          Сумма
                          {categoryTxSort.field === 'amount_tenge' ? (categoryTxSort.direction === 'desc' ? '↓' : '↑') : ''}
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedCategoryModalRows.map((tx) => (
                      <tr key={tx.id} className={`${tableRowClass} border-b`}>
                        <td className="py-2 pr-3 whitespace-nowrap">{tx.date}</td>
                        <td className="py-2 pr-3">{tx.sender?.name || '—'}</td>
                        <td className="py-2 pr-3">{tx.recipient?.name || '—'}</td>
                        <td className={`py-2 pr-3 ${tableTextClass}`}>{tx.purpose || '—'}</td>
                        <td className="py-2 pr-3 text-right font-mono whitespace-nowrap">{fmtFull(tx.amount_tenge)} {TENGE}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AnalyticsDashboard
