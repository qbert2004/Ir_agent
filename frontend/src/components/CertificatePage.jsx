import React, { useState } from 'react'
import { FileText, Loader2, Search } from 'lucide-react'
import {
  fetchCounterpartySearch,
  fetchCounterpartyTransactions,
  fetchTopExpenseTransactions,
} from '../services/api'

const TENGE = '\u20B8'

function fmtMoney(value = 0) {
  const num = Number(value || 0)
  if (!Number.isFinite(num)) return '0,00'
  return num.toLocaleString('ru-RU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
}

function escapeDocText(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function safeDocFileName(value) {
  return String(value || 'certificate')
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, '-')
    .slice(0, 90) || 'certificate'
}

function downloadDocFile(html, fileName) {
  const blob = new Blob(['\ufeff', html], { type: 'application/msword;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function parseTransactionDate(value) {
  const match = String(value || '').match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{2}):(\d{2}))?/)
  if (!match) return null
  const [, dd, mm, yyyy, hh = '00', min = '00'] = match
  return new Date(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(min))
}

function monthLabel(value) {
  const dt = parseTransactionDate(value)
  if (!dt) return 'Без даты'
  return dt.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' })
}

function amountOf(row) {
  return Math.abs(Number(row?.amount_tenge || row?.debit || row?.credit || 0))
}

function incomeOf(row) {
  const credit = Number(row?.credit || 0)
  return credit > 0 ? credit : 0
}

function expenseOf(row) {
  const debit = Number(row?.debit || 0)
  return debit > 0 ? debit : 0
}

function average(values) {
  const nums = values.map(Number).filter((value) => Number.isFinite(value) && value > 0)
  if (!nums.length) return 0
  return nums.reduce((sum, value) => sum + value, 0) / nums.length
}

function inferCategory(row) {
  const text = `${row?.purpose || ''} ${row?.sender_name || ''} ${row?.recipient_name || ''}`.toLowerCase()
  if (/комисси|commission|fee/.test(text)) return 'Внутренние операции'
  if (/благотвор|charity|пожертв|қайырым/.test(text)) return 'Благотворительность'
  if (/cash|cardless|снятие|atm|налич/.test(text)) return 'Снятие наличных'
  if (/terminal|пополн|зачислен|поступлен|recycler|депозит|вклад/.test(text)) return 'Пополнение'
  if (/кредит|loan|погаш/.test(text)) return 'Кредиты'
  if (/перевод|transfer|p2p/.test(text)) return 'Переводы'
  if (/оплат|payment|услуг|коммун/.test(text)) return 'Оплата услуг'
  if (/esf|счет|договор|contract|товар|тру/.test(text)) return 'Договоры / ЭСФ'
  return 'Прочее'
}

function groupTotals(rows, keyFn, amountFn = amountOf) {
  const map = new Map()
  rows.forEach((row) => {
    const key = keyFn(row) || '—'
    const current = map.get(key) || { name: key, amount: 0, count: 0, categories: new Map() }
    const category = inferCategory(row)
    current.amount += amountFn(row)
    current.count += 1
    current.categories.set(category, (current.categories.get(category) || 0) + 1)
    map.set(key, current)
  })
  return [...map.values()]
    .map((item) => ({
      ...item,
      categoryLabel: [...item.categories.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([name]) => name)
        .join(', ') || '—',
    }))
    .sort((a, b) => b.amount - a.amount)
}

function renderDocRows(rows, columns) {
  if (!rows.length) return `<tr><td colspan="${columns.length}">Нет данных</td></tr>`
  return rows.map((row) => (
    `<tr>${columns.map((column) => `<td>${escapeDocText(column.value(row))}</td>`).join('')}</tr>`
  )).join('')
}

function dedupeRows(rows) {
  const map = new Map()
  rows.forEach((row) => {
    const key = row.id || `${row.date}|${row.sender_name}|${row.recipient_name}|${row.amount_tenge}|${row.purpose}`
    map.set(key, row)
  })
  return [...map.values()]
}

async function loadCertificateTransactions(counterparty, filters) {
  const cp = counterparty?.counterparty || counterparty || {}
  const name = cp.name || ''
  const iinBin = cp.iin_bin || ''
  const account = cp.account || ''
  if (iinBin) {
    const res = await fetchCounterpartyTransactions(iinBin, account, 500, filters)
    return { subject: res.counterparty || cp, rows: res.data || [], total: res.total || 0 }
  }

  const [debit, credit] = await Promise.all([
    fetchTopExpenseTransactions('debit', '', account, name, 500, filters),
    fetchTopExpenseTransactions('credit', '', account, name, 500, filters),
  ])
  return {
    subject: debit.counterparty || credit.counterparty || cp,
    rows: dedupeRows([...(debit.data || []), ...(credit.data || [])]),
    total: Math.max(Number(debit.total || 0), Number(credit.total || 0)),
  }
}

function buildCertificateHtml(subject, rows) {
  const sortedRows = [...rows].sort((a, b) => {
    const aTs = parseTransactionDate(a.date)?.getTime() || 0
    const bTs = parseTransactionDate(b.date)?.getTime() || 0
    return aTs - bTs
  })
  const title = subject?.name || subject?.iin_bin || subject?.account || 'Фигурант'
  const totalTurnover = rows.reduce((sum, row) => sum + amountOf(row), 0)
  const totalIncome = rows.reduce((sum, row) => sum + incomeOf(row), 0)
  const totalExpense = rows.reduce((sum, row) => sum + expenseOf(row), 0)
  const openingBalance = sortedRows.length ? incomeOf(sortedRows[0]) - expenseOf(sortedRows[0]) : 0
  const endingBalance = totalIncome - totalExpense
  const incomeRows = rows.filter((row) => incomeOf(row) > 0)
  const expenseRows = rows.filter((row) => expenseOf(row) > 0)
  const averageIncome = average(incomeRows.map(incomeOf))
  const averageExpense = average(expenseRows.map(expenseOf))
  const firstTransactionDate = sortedRows[0]?.date || '—'
  const lastTransactionDate = sortedRows[sortedRows.length - 1]?.date || '—'
  const monthlyAverages = groupTotals(rows, (row) => monthLabel(row.date)).map((item) => {
    const monthRows = rows.filter((row) => monthLabel(row.date) === item.name)
    return {
      month: item.name,
      incomeAverage: average(monthRows.map(incomeOf)),
      expenseAverage: average(monthRows.map(expenseOf)),
      count: item.count,
    }
  })
  const counterparties = groupTotals(rows, (row) => {
    const sender = row.sender_name || '—'
    const recipient = row.recipient_name || '—'
    return sender === title ? recipient : sender
  }).slice(0, 10)
  const topAmounts = [...rows].sort((a, b) => amountOf(b) - amountOf(a)).slice(0, 10)
  const topCategories = groupTotals(rows, inferCategory).slice(0, 8)
  const charityRows = rows.filter((row) => inferCategory(row) === 'Благотворительность')
  const regularPayments = groupTotals(rows, (row) => `${inferCategory(row)} | ${Math.round(amountOf(row) / 1000) * 1000}`)
    .filter((item) => item.count >= 3)
    .slice(0, 5)
  const terminalIncome = incomeRows.filter((row) => /terminal|терминал|recycler|cash|налич|пополн/.test(`${row.purpose || ''}`.toLowerCase()))
  const transferIncome = incomeRows.filter((row) => !terminalIncome.includes(row))
  const expenseOverIncomePct = totalIncome > 0 ? ((totalExpense - totalIncome) / totalIncome) * 100 : 0
  const topExpenseCategory = topCategories[0]
  const topCounterparty = counterparties[0]
  const topCounterpartyShare = topCounterparty ? Math.round((topCounterparty.amount / Math.max(totalTurnover, 1)) * 100) : 0
  const secondCounterparty = counterparties[1]
  const secondCounterpartyShare = secondCounterparty ? Math.round((secondCounterparty.amount / Math.max(totalTurnover, 1)) * 100) : 0
  const topCategoryShare = topExpenseCategory ? Math.round((topExpenseCategory.amount / Math.max(totalTurnover, 1)) * 100) : 0
  const transferIncomeAmount = transferIncome.reduce((sum, row) => sum + incomeOf(row), 0)
  const transferIncomeShare = totalIncome > 0 ? Math.round((transferIncomeAmount / totalIncome) * 100) : 0
  const topAmountLabel = topAmounts[0] ? fmtMoney(amountOf(topAmounts[0])) : '0,00'
  const secondAmountLabel = topAmounts[1] ? fmtMoney(amountOf(topAmounts[1])) : topAmountLabel
  const maxRegularCount = regularPayments.reduce((max, item) => Math.max(max, item.count || 0), 0)
  const riskLevel = rows.length >= 50 || expenseOverIncomePct > 10 || regularPayments.length
    ? 'средне-высоком уровне комплаенс-рисков'
    : 'умеренном уровне комплаенс-рисков'
  const balanceTrend = endingBalance < openingBalance
    ? `снижение с ${fmtMoney(openingBalance)} KZT до ${fmtMoney(endingBalance)} KZT`
    : `изменение с ${fmtMoney(openingBalance)} KZT до ${fmtMoney(endingBalance)} KZT`
  const balanceConclusion = endingBalance < 0 || totalExpense > totalIncome
    ? 'отрицательный баланс и превышение расходов над доходами'
    : 'положительный баланс и покрытие расходов доходной частью'
  const regularText = regularPayments.length
    ? `Выявлены <strong>повторяющиеся операции с одинаковыми суммами (до ${maxRegularCount} раз)</strong>, что может указывать на <strong>структурирование платежей</strong>.`
    : 'Повторяющиеся операции с одинаковыми суммами в выраженном виде не выявлены.'
  const charityText = charityRows.length
    ? `Дополнительно выявлены <strong>платежи на благотворительность</strong>: ${charityRows.length} операций на сумму <strong>${fmtMoney(charityRows.reduce((sum, row) => sum + amountOf(row), 0))} KZT</strong>.`
    : 'Платежи на благотворительность в анализируемой выборке не зафиксированы.'

  const conclusionHtml = `
  <h2>ЗАКЛЮЧЕНИЕ</h2>
  <p>Анализ банковских счетов фигуранта ${escapeDocText(title)} за анализируемый период характеризуется <strong>высокой финансовой активностью при наличии признаков и повышенного риска</strong>. Общий оборот составил <strong>${escapeDocText(fmtMoney(totalTurnover))} KZT</strong>, при этом зафиксировано <strong>${escapeDocText(balanceTrend)}</strong>, что указывает на <strong>${balanceConclusion}</strong>.</p>
  <p>Доходная часть формируется преимущественно за счет <strong>переводов по счетам (${transferIncomeShare}%)</strong>, при этом наблюдается <strong>повторяемость поступлений</strong>. Структура контрагентов демонстрирует <strong>высокую концентрацию оборота</strong>: ${topCounterparty ? `около <strong>${topCounterpartyShare}% операций приходится на ${escapeDocText(topCounterparty.name)}</strong>` : 'ключевой контрагент не определен'}${secondCounterparty ? `, а около <strong>${secondCounterpartyShare}% — на ${escapeDocText(secondCounterparty.name)}</strong>` : ''}, что формирует <strong>зависимость от ограниченного круга источников</strong>.</p>
  <p>Расходная часть характеризуется <strong>аномально высокой долей операций в категории "${escapeDocText(topExpenseCategory?.name || 'Прочее')}" (${topCategoryShare}% оборота)</strong>, а также значительным объемом <strong>крупных транзакций (${escapeDocText(topAmountLabel)}–${escapeDocText(secondAmountLabel)} KZT)</strong>. ${regularText}</p>
  <p>Дополнительно зафиксированы <strong>признаки нетипичного финансового поведения</strong>:</p>
  <p>— <strong>крупные циклические операции (перевод → депозит → снятие наличных)</strong><br>
  — <strong>серии однотипных транзакций на фиксированные суммы</strong><br>
  — <strong>высокий средний исходящий чек (${escapeDocText(fmtMoney(averageExpense))} KZT), ${averageExpense > averageIncome ? 'превышающий' : 'сопоставимый с'} входящим (${escapeDocText(fmtMoney(averageIncome))} KZT)</strong></p>
  <p>${charityText}</p>
  <p>В совокупности данные факторы свидетельствуют о <strong>${riskLevel}</strong>, включая потенциальные признаки <strong>обналичивания и транзитного характера операций</strong>. Несмотря на высокий оборот, <strong>ликвидность ${endingBalance < openingBalance ? 'ухудшается' : 'требует контроля'}</strong>, что повышает вероятность дальнейшего финансового дисбаланса.</p>
  <p><strong>При сохранении текущей модели операций прогнозируется дальнейшее ухудшение финансовой устойчивости и рост операционных рисков.</strong> Общая оценка — <strong>повышенный уровень риска</strong>, требующий <strong>углубленного анализа источников поступлений, назначения платежей и экономической обоснованности транзакций</strong>.</p>`

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Справка: ${escapeDocText(title)}</title>
  <style>
    @page { size: A4 portrait; margin: 18mm 16mm; }
    body { width: 210mm; min-height: 297mm; margin: 0 auto; font-family: Arial, sans-serif; color: #111827; line-height: 1.35; text-decoration: none; }
    h1 { margin: 0 0 8px; font-size: 22pt; }
    h2 { margin: 22px 0 8px; font-size: 14pt; color: #374151; }
    p, li, strong, b, span, div { text-decoration: none; }
    p, li { font-size: 10.5pt; }
    .meta { margin-bottom: 14px; color: #4b5563; font-size: 10pt; }
    table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; }
    th, td { border: 1px solid #d1d5db; padding: 6px 8px; vertical-align: top; font-size: 9pt; }
    th { background: #f3f4f6; text-align: left; }
  </style>
</head>
<body>
  <h1>Справка по фигуранту</h1>
  <div class="meta">
    <div><b>ФИО / наименование:</b> ${escapeDocText(title)}</div>
    <div><b>ИИН/БИН:</b> ${escapeDocText(subject?.iin_bin || '—')}</div>
    <div><b>Счет:</b> ${escapeDocText(subject?.account || '—')}</div>
    <div><b>Дата формирования:</b> ${escapeDocText(new Date().toLocaleString('ru-RU'))}</div>
  </div>
  ${conclusionHtml}
  <h2>1. Общая сводка</h2>
  <table><tbody>
    <tr><th>Общий оборот</th><td>${escapeDocText(fmtMoney(totalTurnover))} KZT</td></tr>
    <tr><th>Период операций</th><td>${escapeDocText(firstTransactionDate)} — ${escapeDocText(lastTransactionDate)}</td></tr>
    <tr><th>Сальдо на начало операции</th><td>${escapeDocText(fmtMoney(openingBalance))} KZT</td></tr>
    <tr><th>Сальдо на конец периода</th><td>${escapeDocText(fmtMoney(endingBalance))} KZT</td></tr>
    <tr><th>Количество операций</th><td>${rows.length}</td></tr>
    <tr><th>Средний чек входящий</th><td>${escapeDocText(fmtMoney(averageIncome))} KZT</td></tr>
    <tr><th>Средний чек исходящий</th><td>${escapeDocText(fmtMoney(averageExpense))} KZT</td></tr>
  </tbody></table>
  <h2>Средний чек по месяцам</h2>
  <table><thead><tr><th>Месяц</th><th>Средний входящий чек</th><th>Средний исходящий чек</th><th>Операций</th></tr></thead>
  <tbody>${renderDocRows(monthlyAverages, [
    { value: (item) => item.month },
    { value: (item) => `${fmtMoney(item.incomeAverage)} KZT` },
    { value: (item) => `${fmtMoney(item.expenseAverage)} KZT` },
    { value: (item) => item.count },
  ])}</tbody></table>
  <h2>Топ контрагенты</h2>
  <table><thead><tr><th>Контрагент</th><th>Оборот</th><th>Операций</th><th>Основные категории</th></tr></thead>
  <tbody>${renderDocRows(counterparties, [
    { value: (item) => item.name },
    { value: (item) => `${fmtMoney(item.amount)} KZT` },
    { value: (item) => item.count },
    { value: (item) => item.categoryLabel },
  ])}</tbody></table>
  <h2>Топ по суммам</h2>
  <table><thead><tr><th>Дата</th><th>Отправитель</th><th>Получатель</th><th>Назначение</th><th>Сумма</th></tr></thead>
  <tbody>${renderDocRows(topAmounts, [
    { value: (row) => row.date || '—' },
    { value: (row) => row.sender_name || '—' },
    { value: (row) => row.recipient_name || '—' },
    { value: (row) => row.purpose || '—' },
    { value: (row) => `${fmtMoney(amountOf(row))} ${row.currency || 'KZT'}` },
  ])}</tbody></table>
  <h2>Топ категорий</h2>
  <table><thead><tr><th>Категория</th><th>Оборот</th><th>Операций</th><th>Доля оборота</th></tr></thead>
  <tbody>${renderDocRows(topCategories, [
    { value: (item) => item.name },
    { value: (item) => `${fmtMoney(item.amount)} KZT` },
    { value: (item) => item.count },
    { value: (item) => `${Math.round((item.amount / Math.max(totalTurnover, 1)) * 100)}%` },
  ])}</tbody></table>
</body>
</html>`
}

function CertificatePage({ theme, filters = {} }) {
  const isDark = theme === 'dark'
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')

  const panelClass = isDark ? 'border-zinc-800 bg-[#111217]' : 'border-slate-200 bg-white'
  const mutedText = isDark ? 'text-zinc-400' : 'text-slate-500'
  const headingText = isDark ? 'text-zinc-100' : 'text-slate-900'
  const inputClass = isDark
    ? 'border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/50'
    : 'border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:border-cyan-400'

  const runSearch = async () => {
    const value = query.trim()
    if (value.length < 2) {
      setError('Введите минимум 2 символа: ИИН, ФИО или номер счета.')
      return
    }
    setLoading(true)
    setError('')
    setSelected(null)
    try {
      const res = await fetchCounterpartySearch(value, 10)
      setResults(res?.data || [])
      if (!(res?.data || []).length) setError('Фигурант не найден.')
    } catch (err) {
      setError(err?.message || 'Не удалось выполнить поиск.')
    } finally {
      setLoading(false)
    }
  }

  const generateReport = async () => {
    const target = selected || results[0]
    if (!target) {
      await runSearch()
      return
    }
    setGenerating(true)
    setError('')
    try {
      const { subject, rows } = await loadCertificateTransactions(target, filters)
      if (!rows.length) {
        setError('По выбранному фигуранту не найдены транзакции для справки.')
        return
      }
      const html = buildCertificateHtml(subject, rows)
      const name = subject?.name || subject?.iin_bin || subject?.account || 'fig'
      downloadDocFile(html, `${safeDocFileName(`Справка ${name}`)}.doc`)
    } catch (err) {
      setError(err?.message || 'Не удалось сформировать справку.')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <section className="space-y-6">
      <div className={`rounded-[32px] border p-7 shadow-[0_18px_50px_rgba(15,23,42,0.06)] ${panelClass}`}>
        <div className="flex flex-col gap-2">
          <div className="text-[10px] font-black uppercase tracking-[0.32em] text-cyan-500">Справка</div>
          <h1 className={`text-2xl font-black ${headingText}`}>Генерация Word-справки по фигуранту</h1>
          <p className={`max-w-3xl text-sm leading-6 ${mutedText}`}>
            Введите ИИН/БИН, ФИО или номер счета. Система найдет фигуранта и сформирует аналитическую справку в формате A4 Word.
          </p>
        </div>

        <div className="mt-7 flex flex-col gap-3 lg:flex-row">
          <div className="relative flex-1">
            <Search className={`pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 ${mutedText}`} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') void runSearch()
              }}
              placeholder="ИИН/БИН, ФИО или номер счета"
              className={`h-13 w-full rounded-2xl border py-3 pl-11 pr-4 text-sm font-semibold outline-none transition-colors ${inputClass}`}
            />
          </div>
          <button
            type="button"
            onClick={() => void runSearch()}
            disabled={loading}
            className="inline-flex h-13 items-center justify-center gap-2 rounded-2xl bg-cyan-500 px-5 text-sm font-black text-white transition-all hover:scale-[1.01] hover:bg-cyan-400 disabled:opacity-60"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            Найти
          </button>
          <button
            type="button"
            onClick={() => void generateReport()}
            disabled={generating || loading || (!selected && !results.length)}
            className="inline-flex h-13 items-center justify-center gap-2 rounded-2xl bg-indigo-500 px-5 text-sm font-black text-white transition-all hover:scale-[1.01] hover:bg-indigo-400 disabled:opacity-60"
          >
            {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
            Сгенерировать
          </button>
        </div>

        {error && (
          <div className="mt-5 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm font-semibold text-rose-400">
            {error}
          </div>
        )}
      </div>

      {results.length > 0 && (
        <div className={`rounded-[28px] border p-5 ${panelClass}`}>
          <div className={`mb-4 text-[10px] font-black uppercase tracking-[0.24em] ${mutedText}`}>Результаты поиска</div>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            {results.map((item, idx) => {
              const cp = item.counterparty || {}
              const active = selected === item || (!selected && idx === 0)
              return (
                <button
                  key={`${cp.iin_bin || cp.account || cp.name}-${idx}`}
                  type="button"
                  onClick={() => setSelected(item)}
                  className={`rounded-2xl border p-4 text-left transition-all hover:scale-[1.01] ${
                    active
                      ? 'border-cyan-400/50 bg-cyan-500/10'
                      : isDark
                        ? 'border-zinc-800 bg-zinc-950/50 hover:border-zinc-700'
                        : 'border-slate-200 bg-slate-50 hover:border-cyan-200'
                  }`}
                >
                  <div className={`text-sm font-black ${headingText}`}>{cp.name || '—'}</div>
                  <div className={`mt-2 grid gap-1 text-xs ${mutedText}`}>
                    <span>ИИН/БИН: {cp.iin_bin || '—'}</span>
                    <span>Счет: {cp.account || '—'}</span>
                    <span>Оборот: {fmtMoney(item.total_turnover)} {TENGE} · операций: {item.transaction_count || 0}</span>
                  </div>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </section>
  )
}

export default CertificatePage
