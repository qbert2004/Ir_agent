import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BarChart,
  Bar,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Sparkles } from 'lucide-react'
import { fetchComparePeriods } from '../services/api'

const TENGE = '\u20B8'

const fmt = (v) => {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)}K`
  return String(v || 0)
}

const fmtFull = (v) => new Intl.NumberFormat('ru-RU').format(v || 0)

function pad2(value) {
  return String(value).padStart(2, '0')
}

function toDateInputValue(date) {
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`
}

function toApiDate(value) {
  if (!value) return ''
  const [yyyy, mm, dd] = String(value).split('-')
  if (!yyyy || !mm || !dd) return ''
  return `${dd}.${mm}.${yyyy}`
}

function buildDefaultComparisonFilters() {
  const now = new Date()
  const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1)
  const currentMonthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0)
  const previousMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1)
  const previousMonthEnd = new Date(now.getFullYear(), now.getMonth(), 0)

  return {
    periodAFrom: toDateInputValue(previousMonthStart),
    periodATo: toDateInputValue(previousMonthEnd),
    periodBFrom: toDateInputValue(currentMonthStart),
    periodBTo: toDateInputValue(currentMonthEnd),
  }
}

function fmtSignedNumber(value, digits = 0) {
  const num = Number(value || 0)
  const abs = Math.abs(num)
  const formatted = new Intl.NumberFormat('ru-RU', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(abs)
  if (num > 0) return `+${formatted}`
  if (num < 0) return `-${formatted}`
  return formatted
}

function fmtSignedPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return 'new'
  }
  const num = Number(value)
  const abs = Math.abs(num)
  const formatted = new Intl.NumberFormat('ru-RU', {
    minimumFractionDigits: 0,
    maximumFractionDigits: abs >= 100 ? 0 : 1,
  }).format(abs)
  if (num > 0) return `+${formatted}%`
  if (num < 0) return `-${formatted}%`
  return '0%'
}

function ComparisonDashboard({ theme, filters = {} }) {
  const isDark = theme === 'dark'
  const activeFilters = filters || {}
  const [comparisonFilters, setComparisonFilters] = useState(() => buildDefaultComparisonFilters())
  const [comparisonData, setComparisonData] = useState(null)
  const [comparisonLoading, setComparisonLoading] = useState(false)
  const [comparisonError, setComparisonError] = useState('')

  const headingText = 'text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-500'
  const subtitleText = 'text-[8px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-600'
  const tableHeaderClass = isDark ? 'text-zinc-500 border-zinc-800' : 'text-slate-400 border-slate-100'
  const tableRowClass = isDark ? 'border-zinc-900/50 text-zinc-100' : 'border-slate-50 text-slate-800'
  const axisColor = isDark ? '#6b7280' : '#9ca3af'
  const tooltipStyle = {
    backgroundColor: isDark ? '#1f2937' : '#ffffff',
    border: `1px solid ${isDark ? '#374151' : '#e5e7eb'}`,
    borderRadius: '8px',
    color: isDark ? '#f3f4f6' : '#111827',
    fontSize: '12px',
  }

  const handleComparisonFieldChange = (field, value) => {
    setComparisonFilters((prev) => ({ ...prev, [field]: value }))
  }

  const loadComparison = useCallback(async () => {
    const payload = {
      dateFromA: toApiDate(comparisonFilters.periodAFrom),
      dateToA: toApiDate(comparisonFilters.periodATo),
      dateFromB: toApiDate(comparisonFilters.periodBFrom),
      dateToB: toApiDate(comparisonFilters.periodBTo),
      limit: 20,
      filters: activeFilters,
    }

    if (!payload.dateFromA || !payload.dateToA || !payload.dateFromB || !payload.dateToB) {
      setComparisonError('Заполните оба периода для сравнения.')
      return
    }

    setComparisonLoading(true)
    setComparisonError('')
    try {
      const res = await fetchComparePeriods(payload)
      setComparisonData(res)
    } catch (e) {
      setComparisonError(e?.message || 'Не удалось получить сравнение периодов.')
    } finally {
      setComparisonLoading(false)
    }
  }, [activeFilters, comparisonFilters])

  useEffect(() => {
    loadComparison()
  }, [loadComparison])

  const comparisonMetrics = comparisonData?.metrics || []
  const comparisonCategories = comparisonData?.categories || []
  const comparisonAnomalies = comparisonData?.anomalies || []
  const countMetricLabels = new Set(['Кол-во транзакций', 'Уникальные контрагенты'])
  const moneyMetrics = comparisonMetrics.filter((metric) => !countMetricLabels.has(metric.label))
  const countMetrics = comparisonMetrics.filter((metric) => countMetricLabels.has(metric.label))

  const comparisonChartData = useMemo(() => (
    moneyMetrics.map((metric) => ({
      label: metric.label,
      periodA: Number(metric.value_a || 0),
      periodB: Number(metric.value_b || 0),
    }))
  ), [moneyMetrics])

  const comparisonChartMax = comparisonChartData.reduce((acc, item) => {
    return Math.max(acc, Number(item.periodA || 0), Number(item.periodB || 0))
  }, 0)

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto pb-12">
      <section className="bento-tile p-6">
        <div className="mx-auto w-full max-w-[920px]">
          {/*
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-indigo-500" />
              <h1 className="text-lg font-black text-slate-900 dark:text-zinc-100">Сравнение периодов</h1>
            </div>
            <p className="text-sm text-slate-500 dark:text-zinc-400">
              Отдельная страница для сравнения двух временных окон по KPI, категориям и изменениям.
            </p>
          </div>
          */}

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="rounded-2xl border border-slate-200/70 bg-slate-50/80 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
              <div className={headingText}>Период A</div>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="space-y-1">
                  <span className={subtitleText}>От</span>
                  <input
                    type="date"
                    value={comparisonFilters.periodAFrom}
                    onChange={(e) => handleComparisonFieldChange('periodAFrom', e.target.value)}
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
                  />
                </label>
                <label className="space-y-1">
                  <span className={subtitleText}>До</span>
                  <input
                    type="date"
                    value={comparisonFilters.periodATo}
                    onChange={(e) => handleComparisonFieldChange('periodATo', e.target.value)}
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
                  />
                </label>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200/70 bg-slate-50/80 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
              <div className={headingText}>Период B</div>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="space-y-1">
                  <span className={subtitleText}>От</span>
                  <input
                    type="date"
                    value={comparisonFilters.periodBFrom}
                    onChange={(e) => handleComparisonFieldChange('periodBFrom', e.target.value)}
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
                  />
                </label>
                <label className="space-y-1">
                  <span className={subtitleText}>До</span>
                  <input
                    type="date"
                    value={comparisonFilters.periodBTo}
                    onChange={(e) => handleComparisonFieldChange('periodBTo', e.target.value)}
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
                  />
                </label>
              </div>
            </div>

            {/*
            <button
              type="button"
              onClick={loadComparison}
              disabled={comparisonLoading}
              className="rounded-2xl bg-indigo-600 px-5 py-3 text-xs font-black uppercase tracking-[0.18em] text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {comparisonLoading ? 'Сравниваем...' : 'Сравнить'}
            </button>
            */}
          </div>
        </div>

        {comparisonError && (
          <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-600 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200">
            {comparisonError}
          </div>
        )}
      </section>

      {/*
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-2">
        {moneyMetrics.map((metric) => {
          const positive = Number(metric?.delta?.absolute || 0) >= 0
          return (
            <div key={metric.label} className="bento-tile p-5">
              <div className="flex items-start justify-between gap-3">
                <span className={headingText}>{metric.label}</span>
                <span className={`rounded-full px-2.5 py-1 text-[10px] font-black ${
                  positive
                    ? 'bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-300'
                    : 'bg-rose-50 text-rose-600 dark:bg-rose-500/10 dark:text-rose-300'
                }`}>
                  {fmtSignedPercent(metric?.delta?.percent)}
                </span>
              </div>
              <div className="mt-5 grid grid-cols-2 gap-3">
                <div>
                  <div className={subtitleText}>A</div>
                  <div className="mt-1 text-xl font-black text-slate-900 dark:text-zinc-100">
                    {`${fmt(metric.value_a)} ${TENGE}`}
                  </div>
                </div>
                <div>
                  <div className={subtitleText}>B</div>
                  <div className="mt-1 text-xl font-black text-slate-900 dark:text-zinc-100">
                    {`${fmt(metric.value_b)} ${TENGE}`}
                  </div>
                </div>
              </div>
              <div className="mt-4 border-t border-slate-100 pt-4 text-sm font-bold text-slate-500 dark:border-zinc-800 dark:text-zinc-400">
                Изменение: {`${fmtSignedNumber(metric?.delta?.absolute)} ${TENGE}`}
              </div>
            </div>
          )
        })}
      </section>
      */}

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {countMetrics.map((metric) => {
          const positive = Number(metric?.delta?.absolute || 0) >= 0
          return (
            <div key={metric.label} className="bento-tile p-6">
              <div className="flex items-start justify-between gap-3">
                <div className={headingText}>{metric.label}</div>
                <span className={`rounded-full px-3 py-1 text-[10px] font-black ${
                  positive
                    ? 'bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-300'
                    : 'bg-rose-50 text-rose-600 dark:bg-rose-500/10 dark:text-rose-300'
                }`}>
                  {fmtSignedPercent(metric?.delta?.percent)}
                </span>
              </div>

              <div className="mt-6 grid grid-cols-2 gap-4">
                <div className="rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 dark:border-zinc-800 dark:bg-zinc-900/50">
                  <div className={subtitleText}>Период A</div>
                  <div className="mt-2 text-2xl font-black text-slate-900 dark:text-zinc-100">
                    {fmtFull(metric.value_a)}
                  </div>
                </div>
                <div className="rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 dark:border-zinc-800 dark:bg-zinc-900/50">
                  <div className={subtitleText}>Период B</div>
                  <div className="mt-2 text-2xl font-black text-slate-900 dark:text-zinc-100">
                    {fmtFull(metric.value_b)}
                  </div>
                </div>
              </div>

              <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 dark:border-zinc-800">
                <span className="text-sm font-bold text-slate-500 dark:text-zinc-400">Абсолютная разница</span>
                <span className={`text-lg font-black ${positive ? 'text-emerald-500' : 'text-rose-500'}`}>
                  {fmtSignedNumber(metric?.delta?.absolute)}
                </span>
              </div>
            </div>
          )
        })}
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.25fr)_380px]">
        <div className="bento-tile p-6">
          <div>
            <h3 className={headingText}>A vs B</h3>
            <p className="mt-2 text-sm text-slate-500 dark:text-zinc-400">
              Быстрое сравнение ключевых метрик по двум периодам.
            </p>
          </div>

          <div className="mt-6 h-[360px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={comparisonChartData} margin={{ top: 10, right: 10, left: 0, bottom: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#27272a' : '#e5e7eb'} vertical={false} />
                <XAxis dataKey="label" tick={{ fill: axisColor, fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis
                  tickFormatter={fmt}
                  tick={{ fill: axisColor, fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  width={56}
                  domain={[0, comparisonChartMax > 0 ? comparisonChartMax * 1.12 : 1]}
                />
                <Tooltip contentStyle={tooltipStyle} formatter={(value) => [fmtFull(value), 'Значение']} />
                <Bar dataKey="periodA" name="Период A" radius={[6, 6, 0, 0]} fill="#6366f1" />
                <Bar dataKey="periodB" name="Период B" radius={[6, 6, 0, 0]} fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bento-tile p-6">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-amber-500" />
            <h3 className={headingText}>Что изменилось</h3>
          </div>

          <div className="mt-5 space-y-3">
            {comparisonAnomalies.length > 0 ? comparisonAnomalies.map((item) => (
              <div
                key={item}
                className="rounded-2xl border border-amber-200/70 bg-amber-50/80 px-4 py-3 text-sm text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200"
              >
                {item}
              </div>
            )) : (
              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-500 dark:border-zinc-800 dark:bg-zinc-900/50 dark:text-zinc-400">
                Выраженных изменений пока не найдено.
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="bento-tile p-6">
        <div>
          <h3 className={headingText}>Категории с наибольшим изменением</h3>
          <p className="mt-2 text-sm text-slate-500 dark:text-zinc-400">
            Разница рассчитывается по обороту в тенге.
          </p>
        </div>

        <div className="mt-6 overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className={`${tableHeaderClass} border-b`}>
                <th className="py-3 pr-4 text-left">Категория</th>
                <th className="py-3 px-4 text-right">Период A</th>
                <th className="py-3 px-4 text-right">Период B</th>
                <th className="py-3 px-4 text-right">Разница</th>
                <th className="py-3 pl-4 text-right">%</th>
              </tr>
            </thead>
            <tbody>
              {comparisonCategories.map((item) => {
                const positive = Number(item.delta || 0) >= 0
                return (
                  <tr key={item.category} className={`${tableRowClass} border-b`}>
                    <td className="py-3 pr-4 font-semibold">{item.category}</td>
                    <td className="py-3 px-4 text-right font-mono">{fmtFull(item.value_a)} {TENGE}</td>
                    <td className="py-3 px-4 text-right font-mono">{fmtFull(item.value_b)} {TENGE}</td>
                    <td className={`py-3 px-4 text-right font-mono ${positive ? 'text-emerald-500' : 'text-rose-500'}`}>
                      {fmtSignedNumber(item.delta)} {TENGE}
                    </td>
                    <td className={`py-3 pl-4 text-right font-black ${positive ? 'text-emerald-500' : 'text-rose-500'}`}>
                      {fmtSignedPercent(item.delta_percent)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {!comparisonLoading && comparisonCategories.length === 0 && (
            <div className="py-6 text-sm text-slate-500 dark:text-zinc-400">
              Нет данных по категориям для выбранных периодов.
            </div>
          )}
        </div>
      </section>
    </div>
  )
}

export default ComparisonDashboard
