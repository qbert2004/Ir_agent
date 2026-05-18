import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import {
  ChevronLeft,
  ChevronRight,
  FileSpreadsheet,
  Loader2,
  LocateFixed,
  Maximize2,
  Minimize2,
  FileText,
  RefreshCw,
  Search,
  Waypoints,
} from 'lucide-react'
import {
  fetchCounterpartyTransactions,
  fetchEdgeTransactions,
  fetchCounterpartyGraph,
  fetchCounterpartySearch,
  fetchTopCounterparties,
} from '../services/api'
import { autoFitWorksheetColumns } from '../utils/xlsx'

function formatCompactAmount(value = 0) {
  const num = Number(value || 0)
  if (!Number.isFinite(num)) return '0 тг'
  if (num >= 1_000_000_000) return `${(num / 1_000_000_000).toFixed(1)}B тг`
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M тг`
  if (num >= 1_000) return `${(num / 1_000).toFixed(0)}K тг`
  return `${num.toFixed(0)} тг`
}

function formatFullAmount(value = 0) {
  const num = Number(value || 0)
  if (!Number.isFinite(num)) return '0'
  return num.toLocaleString('ru-RU', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })
}

function truncateLabel(value = '', max = 24) {
  if (!value) return '—'
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}

function escapeDocText(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function safeDocFileName(value) {
  return String(value || 'graph-report')
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, '-')
    .slice(0, 90) || 'graph-report'
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

function inferCategory(row) {
  const text = `${row?.purpose || ''} ${row?.sender_name || ''} ${row?.recipient_name || ''}`.toLowerCase()
  if (/благотвор|charity|пожертв|қайырым/.test(text)) return 'Благотворительность'
  if (/cash|cardless|снятие|atm|налич/.test(text)) return 'Снятие наличных'
  if (/terminal|пополн|зачислен|поступлен|recycler|депозит|вклад/.test(text)) return 'Пополнение'
  if (/кредит|loan|погаш/.test(text)) return 'Кредиты'
  if (/перевод|transfer|p2p/.test(text)) return 'Переводы'
  if (/оплат|payment|услуг|коммун/.test(text)) return 'Оплата услуг'
  if (/esf|счет|договор|contract|товар|тру/.test(text)) return 'Договоры / ЭСФ'
  return 'Прочее'
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

function buildTransactionExportRows(rows) {
  return (rows || []).map((row) => ({
    'Дата': row.date || '',
    'Отправитель': row.sender_name || '',
    'Счет отправителя': row.sender_account || row.sender?.account || '',
    'ИИН/БИН отправителя': row.sender_iin_bin || row.sender?.iin_bin || '',
    'Получатель': row.recipient_name || '',
    'Счет получателя': row.recipient_account || row.recipient?.account || '',
    'ИИН/БИН получателя': row.recipient_iin_bin || row.recipient?.iin_bin || '',
    'Назначение': row.purpose || '',
    'Валюта': row.currency || 'KZT',
    'Сумма': Number(row.amount_tenge || row.debit || row.credit || 0),
  }))
}

function average(values) {
  const nums = values.map(Number).filter((value) => Number.isFinite(value) && value > 0)
  if (!nums.length) return 0
  return nums.reduce((sum, value) => sum + value, 0) / nums.length
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
  if (!rows.length) {
    return `<tr><td colspan="${columns.length}">Нет данных</td></tr>`
  }
  return rows.map((row) => (
    `<tr>${columns.map((column) => `<td>${escapeDocText(column.value(row))}</td>`).join('')}</tr>`
  )).join('')
}

function mapRange(value, inMin, inMax, outMin, outMax) {
  if (!Number.isFinite(value) || inMax <= inMin) return outMin
  const ratio = Math.max(0, Math.min(1, (value - inMin) / (inMax - inMin)))
  return outMin + ratio * (outMax - outMin)
}

function snapshotsEqual(a, b) {
  if (!a || !b) return false
  return JSON.stringify(a) === JSON.stringify(b)
}

function buildElements(graph) {
  const nodes = graph?.nodes || []
  const edges = graph?.edges || []
  const maxTurnover = Math.max(...nodes.map((node) => Number(node.total_turnover || 0)), 1)
  const maxAmount = Math.max(...edges.map((edge) => Number(edge.amount || 0)), 1)

  return [
    ...nodes.map((node) => ({
      data: {
        id: node.id,
        label: node.label || node.iin_bin || node.id,
        shortLabel: truncateLabel(node.label || node.iin_bin || node.id, 22),
        iinBin: node.iin_bin || node.id,
        level: Number(node.level || 0),
        totalTurnover: Number(node.total_turnover || 0),
        size:
          node.id === graph.center_iin_bin
            ? 92
            : mapRange(Number(node.total_turnover || 0), 0, maxTurnover, 42, 78),
        isCenter: node.id === graph.center_iin_bin ? 1 : 0,
      },
    })),
    ...edges.map((edge, index) => ({
      data: {
        id: `${edge.source}-${edge.target}-${index}`,
        source: edge.source,
        target: edge.target,
        amount: Number(edge.amount || 0),
        txCount: Number(edge.tx_count || 0),
        width: mapRange(Number(edge.amount || 0), 0, maxAmount, 2.5, 8),
      },
    })),
  ]
}

function NetworkGraph({ theme = 'light', externalFocus = null }) {
  const isDark = theme === 'dark'
  const graphRef = useRef(null)
  const graphShellRef = useRef(null)
  const cyRef = useRef(null)
  const selectedNodeRef = useRef(null)
  const selectedEdgeRef = useRef(null)
  const historyRef = useRef([])
  const historyCursorRef = useRef(-1)
  const applyingSnapshotRef = useRef(false)
  const historyResetPendingRef = useRef(true)
  const viewportSnapshotTimerRef = useRef(null)
  const dragStateRef = useRef({
    draggedId: null,
    lastPosition: null,
    pendingDelta: { x: 0, y: 0 },
    frameId: null,
    inertiaFrameId: null,
    affectedNodes: null,
    weights: new Map(),
    velocity: { x: 0, y: 0 },
    waterPhase: 0,
    rippleStrength: 0,
  })

  const [topSeeds, setTopSeeds] = useState([])
  const [graphData, setGraphData] = useState(null)
  const [focusNode, setFocusNode] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedEdge, setSelectedEdge] = useState(null)
  const [manualIin, setManualIin] = useState('')
  const [manualName, setManualName] = useState('')
  const [depth, setDepth] = useState('2')
  const [maxNeighbors, setMaxNeighbors] = useState('6')
  const [loadingSeeds, setLoadingSeeds] = useState(true)
  const [loadingGraph, setLoadingGraph] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [historyCursor, setHistoryCursor] = useState(-1)
  const [historySize, setHistorySize] = useState(0)
  const [error, setError] = useState('')
  const [edgeModal, setEdgeModal] = useState({
    open: false,
    loading: false,
    error: '',
    title: '',
    emptyText: 'По этой связи транзакции не найдены.',
    total: 0,
    rows: [],
  })
  const externalFocusIin = String(externalFocus?.iinBin || '').trim()
  const externalFocusName = String(externalFocus?.name || '').trim()
  const externalFocusRequestId = externalFocus?.requestId || 0

  const shellClass = isDark
    ? 'border-zinc-800 bg-[#111217]'
    : 'border-slate-200 bg-white'
  const panelClass = isDark
    ? 'border-zinc-800/90 bg-zinc-950/60'
    : 'border-slate-200 bg-white'
  const mutedText = isDark ? 'text-zinc-400' : 'text-slate-500'
  const headingText = isDark ? 'text-zinc-100' : 'text-slate-900'
  const subtleBg = isDark ? 'bg-zinc-900/70' : 'bg-slate-50'
  const chipClass = isDark
    ? 'border-zinc-800 bg-zinc-900/70 text-zinc-200 hover:border-indigo-500/50 hover:bg-zinc-900'
    : 'border-slate-200 bg-white text-slate-700 hover:border-cyan-300 hover:bg-cyan-50/50'

  useEffect(() => {
    selectedNodeRef.current = selectedNode
  }, [selectedNode])

  useEffect(() => {
    selectedEdgeRef.current = selectedEdge
  }, [selectedEdge])

  const syncHistoryState = useCallback((cursor, size) => {
    historyCursorRef.current = cursor
    setHistoryCursor(cursor)
    setHistorySize(size)
  }, [])

  const buildGraphSnapshot = useCallback((cy) => {
    if (!cy || cy.destroyed()) return null

    return {
      zoom: cy.zoom(),
      pan: { ...cy.pan() },
      nodePositions: cy.nodes().map((node) => ({
        id: node.id(),
        x: node.position('x'),
        y: node.position('y'),
      })),
      selectedNode: selectedNodeRef.current,
      selectedEdge: selectedEdgeRef.current,
    }
  }, [])

  const resetGraphHistory = useCallback(
    (snapshot) => {
      historyRef.current = snapshot ? [snapshot] : []
      syncHistoryState(snapshot ? 0 : -1, snapshot ? 1 : 0)
    },
    [syncHistoryState],
  )

  const pushGraphHistory = useCallback(
    (cy) => {
      if (applyingSnapshotRef.current) return

      const snapshot = buildGraphSnapshot(cy)
      if (!snapshot) return

      const trimmedHistory =
        historyCursorRef.current >= 0
          ? historyRef.current.slice(0, historyCursorRef.current + 1)
          : []
      const lastSnapshot = trimmedHistory[trimmedHistory.length - 1]
      if (lastSnapshot && snapshotsEqual(lastSnapshot, snapshot)) {
        return
      }

      const nextHistory = [...trimmedHistory, snapshot].slice(-40)
      historyRef.current = nextHistory
      syncHistoryState(nextHistory.length - 1, nextHistory.length)
    },
    [buildGraphSnapshot, syncHistoryState],
  )

  const applyGraphSnapshot = useCallback((snapshot) => {
    const cy = cyRef.current
    if (!cy || cy.destroyed() || !snapshot) return

    applyingSnapshotRef.current = true
    cy.stop()

    cy.batch(() => {
      snapshot.nodePositions.forEach(({ id, x, y }) => {
        const node = cy.getElementById(id)
        if (node && node.length > 0) {
          node.position({ x, y })
        }
      })

      cy.zoom(snapshot.zoom)
      cy.pan(snapshot.pan)
      cy.elements().unselect()
    })

    setSelectedNode(snapshot.selectedNode || null)
    setSelectedEdge(snapshot.selectedEdge || null)

    requestAnimationFrame(() => {
      cy.resize()
      applyingSnapshotRef.current = false
    })
  }, [])

  const navigateHistory = useCallback(
    (direction) => {
      const nextIndex = historyCursorRef.current + direction
      if (nextIndex < 0 || nextIndex >= historyRef.current.length) return

      applyGraphSnapshot(historyRef.current[nextIndex])
      syncHistoryState(nextIndex, historyRef.current.length)
    },
    [applyGraphSnapshot, syncHistoryState],
  )

  const toggleFullscreen = useCallback(async () => {
    const element = graphShellRef.current
    if (!element) return

    try {
      if (document.fullscreenElement === element) {
        await document.exitFullscreen()
        return
      }

      if (document.fullscreenElement && document.exitFullscreen) {
        await document.exitFullscreen()
      }

      await element.requestFullscreen()
    } catch {
      // Ignore fullscreen API failures and keep standard graph view.
    }
  }, [])

  const centerGraph = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.destroyed()) return

    const elements = cy.elements()
    if (!elements || elements.empty()) return

    cy.animate(
      {
        fit: {
          eles: elements,
          padding: 72,
        },
      },
      {
        duration: 480,
        easing: 'ease-out-cubic',
        complete: () => pushGraphHistory(cy),
      },
    )
  }, [pushGraphHistory])

  useEffect(() => {
    historyResetPendingRef.current = true
    resetGraphHistory(null)
  }, [graphData, resetGraphHistory])

  useEffect(() => {
    const handleFullscreenChange = () => {
      const active = document.fullscreenElement === graphShellRef.current
      setIsFullscreen(active)

      requestAnimationFrame(() => {
        if (cyRef.current) {
          cyRef.current.resize()
        }
      })
    }

    document.addEventListener('fullscreenchange', handleFullscreenChange)
    return () => {
      document.removeEventListener('fullscreenchange', handleFullscreenChange)
    }
  }, [])

  const loadGraph = useCallback(async (target, options = {}) => {
    const nextIin = String(target?.iinBin || target?.id || options.manualIin || '').trim()
    if (!nextIin) return

    setLoadingGraph(true)
    setError('')
    setSelectedEdge(null)

    try {
      const res = await fetchCounterpartyGraph(nextIin, depth, maxNeighbors)
      const center =
        (res.nodes || []).find((node) => node.id === res.center_iin_bin) ||
        (res.nodes || [])[0] ||
        null

      setGraphData(res)
      setFocusNode({
        iinBin: res.center_iin_bin || nextIin,
        label: center?.label || target?.name || nextIin,
      })
      setSelectedNode(
        center
          ? {
              id: center.id,
              label: center.label,
              iinBin: center.iin_bin || center.id,
              level: center.level,
              totalTurnover: center.total_turnover,
            }
          : null,
      )
      setManualIin(res.center_iin_bin || nextIin)
      setManualName(center?.label || target?.name || '')
    } catch (err) {
      setError(err?.message || 'Не удалось построить граф связей')
    } finally {
      setLoadingGraph(false)
    }
  }, [depth, maxNeighbors])

  const handleBuildGraph = useCallback(async () => {
    const nextIin = manualIin.trim()
    const nextName = manualName.trim()
    const normalizedName = nextName.toLowerCase()

    if (nextIin) {
      await loadGraph({ iinBin: nextIin, name: nextName || nextIin }, { manualIin: nextIin })
      return
    }

    if (!nextName) {
      setError('Введите IIN/BIN или имя контрагента')
      return
    }

    setError('')
    setLoadingGraph(true)
    setSelectedEdge(null)

    try {
      const searchResult = await fetchCounterpartySearch(nextName, 1)
      const match = searchResult?.data?.[0]?.counterparty

      if (!match?.iin_bin) {
        throw new Error('Контрагент по имени не найден')
      }

      setManualIin(match.iin_bin)
      setManualName(match.name || nextName)
      await loadGraph(
        { iinBin: match.iin_bin, name: match.name || nextName },
        { manualIin: match.iin_bin },
      )
    } catch (err) {
      const fallbackMatch = topSeeds.find((item) =>
        item?.name?.toLowerCase().includes(normalizedName),
      )

      if (fallbackMatch?.iinBin) {
        setManualIin(fallbackMatch.iinBin)
        setManualName(fallbackMatch.name || nextName)
        await loadGraph(
          { iinBin: fallbackMatch.iinBin, name: fallbackMatch.name || nextName },
          { manualIin: fallbackMatch.iinBin },
        )
        return
      }
      setLoadingGraph(false)

      const message = String(err?.message || '').trim()
      if (!message || /not found/i.test(message)) {
        setError('Контрагент по имени не найден')
        return
      }
      setError(message)
    }
  }, [loadGraph, manualIin, manualName, topSeeds])

  const openEdgeTransactions = useCallback(async (edge) => {
    if (!edge?.source || !edge?.target) return

    setEdgeModal({
      open: true,
      loading: true,
      error: '',
      title: `${edge.source} ↔ ${edge.target}`,
      emptyText: 'По этой связи транзакции не найдены.',
      total: 0,
      rows: [],
    })

    try {
      const res = await fetchEdgeTransactions(edge.source, edge.target, 300)
      setEdgeModal({
        open: true,
        loading: false,
        error: '',
        title: `${res.source?.name || edge.source} ↔ ${res.target?.name || edge.target}`,
        emptyText: 'По этой связи транзакции не найдены.',
        total: res.total || 0,
        rows: res.data || [],
      })
    } catch (err) {
      setEdgeModal((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Не удалось загрузить транзакции между узлами',
      }))
    }
  }, [])

  const openNodeTransactions = useCallback(async (node) => {
    if (!node?.iinBin) return

    setEdgeModal({
      open: true,
      loading: true,
      error: '',
      title: node.label || node.iinBin,
      emptyText: 'По этому контрагенту транзакции не найдены.',
      total: 0,
      rows: [],
    })

    try {
      const res = await fetchCounterpartyTransactions(node.iinBin, '', 300)
      setEdgeModal({
        open: true,
        loading: false,
        error: '',
        title: res.counterparty?.name || node.label || node.iinBin,
        emptyText: 'По этому контрагенту транзакции не найдены.',
        total: res.total || 0,
        rows: res.data || [],
      })
    } catch (err) {
      setEdgeModal((prev) => ({
        ...prev,
        loading: false,
        error: err?.message || 'Не удалось загрузить транзакции контрагента',
      }))
    }
  }, [])

  const exportEdgeModalExcel = useCallback(async () => {
    const rows = edgeModal.rows || []
    if (!rows.length) return

    const XLSX = await import('xlsx')
    const workbook = XLSX.utils.book_new()
    const exportRows = buildTransactionExportRows(rows)
    const worksheet = XLSX.utils.json_to_sheet(exportRows)
    autoFitWorksheetColumns(worksheet, exportRows)
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Transactions')
    XLSX.writeFile(workbook, `${safeDocFileName(`${edgeModal.title || 'graph'}-transactions`)}.xlsx`)
  }, [edgeModal.rows, edgeModal.title])

  const downloadNodeReport = useCallback(async (node) => {
    if (!node?.iinBin || reportLoading) return

    setReportLoading(true)
    try {
      const res = await fetchCounterpartyTransactions(node.iinBin, '', 500)
      const rows = res?.data || []
      const sortedRows = [...rows].sort((a, b) => {
        const aTs = parseTransactionDate(a.date)?.getTime() || 0
        const bTs = parseTransactionDate(b.date)?.getTime() || 0
        return aTs - bTs
      })
      const firstTransactionDate = sortedRows[0]?.date || '—'
      const lastTransactionDate = sortedRows[sortedRows.length - 1]?.date || '—'
      const title = res?.counterparty?.name || node.label || node.iinBin
      const totalTurnover = rows.reduce((sum, row) => sum + amountOf(row), 0)
      const totalIncome = rows.reduce((sum, row) => sum + incomeOf(row), 0)
      const totalExpense = rows.reduce((sum, row) => sum + expenseOf(row), 0)
      const openingBalance = sortedRows.length ? incomeOf(sortedRows[0]) - expenseOf(sortedRows[0]) : 0
      const endingBalance = totalIncome - totalExpense
      const incomeRows = rows.filter((row) => incomeOf(row) > 0)
      const expenseRows = rows.filter((row) => expenseOf(row) > 0)
      const averageIncome = average(incomeRows.map(incomeOf))
      const averageExpense = average(expenseRows.map(expenseOf))
      const monthlyAverages = groupTotals(rows, (row) => monthLabel(row.date))
        .map((item) => ({
          month: item.name,
          incomeAverage: average(rows.filter((row) => monthLabel(row.date) === item.name).map(incomeOf)),
          expenseAverage: average(rows.filter((row) => monthLabel(row.date) === item.name).map(expenseOf)),
          count: item.count,
        }))
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
      const topAmountLabel = topAmounts[0] ? formatFullAmount(amountOf(topAmounts[0])) : '0,00'
      const secondAmountLabel = topAmounts[1] ? formatFullAmount(amountOf(topAmounts[1])) : topAmountLabel
      const maxRegularCount = regularPayments.reduce((max, item) => Math.max(max, item.count || 0), 0)
      const riskLevel = rows.length >= 50 || expenseOverIncomePct > 10 || regularPayments.length
        ? 'средне-высоком уровне комплаенс-рисков'
        : 'умеренном уровне комплаенс-рисков'
      const balanceTrend = endingBalance < openingBalance
        ? `снижение с ${formatFullAmount(openingBalance)} KZT до ${formatFullAmount(endingBalance)} KZT`
        : `изменение с ${formatFullAmount(openingBalance)} KZT до ${formatFullAmount(endingBalance)} KZT`
      const balanceConclusion = endingBalance < 0 || totalExpense > totalIncome
        ? 'отрицательный баланс и превышение расходов над доходами'
        : 'положительный баланс и покрытие расходов доходной частью'
      const regularText = regularPayments.length
        ? `Выявлены <strong>повторяющиеся операции с одинаковыми суммами (до ${maxRegularCount} раз)</strong>, что может указывать на <strong>структурирование платежей</strong>.`
        : 'Повторяющиеся операции с одинаковыми суммами в выраженном виде не выявлены.'
      const charityText = charityRows.length
        ? `Дополнительно выявлены <strong>платежи на благотворительность</strong>: ${charityRows.length} операций на сумму <strong>${formatFullAmount(charityRows.reduce((sum, row) => sum + amountOf(row), 0))} KZT</strong>.`
        : 'Платежи на благотворительность в анализируемой выборке не зафиксированы.'
      const conclusionHtml = `
  <h2>ЗАКЛЮЧЕНИЕ</h2>
  <p>Анализ банковских счетов фигуранта ${escapeDocText(title)} за анализируемый период характеризуется <strong>высокой финансовой активностью при наличии признаков и повышенного риска</strong>. Общий оборот составил <strong>${escapeDocText(formatFullAmount(totalTurnover))} KZT</strong>, при этом зафиксировано <strong>${escapeDocText(balanceTrend)}</strong>, что указывает на <strong>${balanceConclusion}</strong>.</p>

  <p>Доходная часть формируется преимущественно за счет <strong>переводов по счетам (${transferIncomeShare}%)</strong>, при этом наблюдается <strong>повторяемость поступлений</strong>, что может свидетельствовать о циклическом характере операций. В то же время структура контрагентов демонстрирует <strong>высокую концентрацию оборота</strong>: ${topCounterparty ? `около <strong>${topCounterpartyShare}% операций приходится на ${escapeDocText(topCounterparty.name)}</strong>` : 'ключевой контрагент не определен'}${secondCounterparty ? `, а около <strong>${secondCounterpartyShare}% — на ${escapeDocText(secondCounterparty.name)}</strong>` : ''}, что формирует <strong>зависимость от ограниченного круга источников</strong>.</p>

  <p>Расходная часть характеризуется <strong>аномально высокой долей операций в категории "${escapeDocText(topExpenseCategory?.name || 'Прочее')}" (${topCategoryShare}% оборота)</strong>, а также значительным объемом <strong>крупных транзакций (${escapeDocText(topAmountLabel)}–${escapeDocText(secondAmountLabel)} KZT)</strong>, включая <strong>многочисленные переводы между счетами, депозитами и последующее снятие наличных</strong>. ${regularText}</p>

  <p>Дополнительно зафиксированы <strong>признаки нетипичного финансового поведения</strong>:</p>
  <p>— <strong>крупные циклические операции (перевод → депозит → снятие наличных)</strong><br>
  — <strong>серии однотипных транзакций на фиксированные суммы</strong><br>
  — <strong>высокий средний исходящий чек (${escapeDocText(formatFullAmount(averageExpense))} KZT), ${averageExpense > averageIncome ? 'превышающий' : 'сопоставимый с'} входящим (${escapeDocText(formatFullAmount(averageIncome))} KZT)</strong></p>

  <p>${charityText}</p>

  <p>В совокупности данные факторы свидетельствуют о <strong>${riskLevel}</strong>, включая потенциальные признаки <strong>обналичивания и транзитного характера операций</strong>. Несмотря на высокий оборот, <strong>ликвидность ${endingBalance < openingBalance ? 'ухудшается' : 'требует контроля'}</strong>, что повышает вероятность дальнейшего финансового дисбаланса.</p>

  <p><strong>При сохранении текущей модели операций прогнозируется дальнейшее ухудшение финансовой устойчивости и рост операционных рисков.</strong> Общая оценка — <strong>повышенный уровень риска</strong>, требующий <strong>углубленного анализа источников поступлений, назначения платежей и экономической обоснованности транзакций</strong>.</p>`

      const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Справка по графу: ${escapeDocText(title)}</title>
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
  <h1>Справка по контрагенту графа</h1>
  <div class="meta">
    <div><b>ФИО / наименование:</b> ${escapeDocText(title)}</div>
    <div><b>ИИН/БИН:</b> ${escapeDocText(node.iinBin)}</div>
    <div><b>Дата формирования:</b> ${escapeDocText(new Date().toLocaleString('ru-RU'))}</div>
  </div>

  ${conclusionHtml}

  <h2>1. Общая сводка</h2>
  <table>
    <tbody>
      <tr><th>Общий оборот</th><td>${escapeDocText(formatFullAmount(totalTurnover))} KZT</td></tr>
      <tr><th>Период операций</th><td>${escapeDocText(firstTransactionDate)} — ${escapeDocText(lastTransactionDate)}</td></tr>
      <tr><th>Сальдо на начало операции</th><td>${escapeDocText(formatFullAmount(openingBalance))} KZT</td></tr>
      <tr><th>Сальдо на конец периода</th><td>${escapeDocText(formatFullAmount(endingBalance))} KZT</td></tr>
      <tr><th>Количество операций</th><td>${rows.length}</td></tr>
      <tr><th>Средний чек входящий</th><td>${escapeDocText(formatFullAmount(averageIncome))} KZT</td></tr>
      <tr><th>Средний чек исходящий</th><td>${escapeDocText(formatFullAmount(averageExpense))} KZT</td></tr>
    </tbody>
  </table>

  <h2>Средний чек по месяцам</h2>
  <table>
    <thead><tr><th>Месяц</th><th>Средний входящий чек</th><th>Средний исходящий чек</th><th>Операций</th></tr></thead>
    <tbody>${renderDocRows(monthlyAverages, [
      { value: (item) => item.month },
      { value: (item) => `${formatFullAmount(item.incomeAverage)} KZT` },
      { value: (item) => `${formatFullAmount(item.expenseAverage)} KZT` },
      { value: (item) => item.count },
    ])}</tbody>
  </table>

  <h2>Топ контрагенты</h2>
  <table>
    <thead><tr><th>Контрагент</th><th>Оборот</th><th>Операций</th><th>Основные категории</th></tr></thead>
    <tbody>${renderDocRows(counterparties, [
      { value: (item) => item.name },
      { value: (item) => `${formatFullAmount(item.amount)} KZT` },
      { value: (item) => item.count },
      { value: (item) => item.categoryLabel },
    ])}</tbody>
  </table>

  <h2>Топ по суммам</h2>
  <table>
    <thead><tr><th>Дата</th><th>Отправитель</th><th>Получатель</th><th>Назначение</th><th>Сумма</th></tr></thead>
    <tbody>${renderDocRows(topAmounts, [
      { value: (row) => row.date || '—' },
      { value: (row) => row.sender_name || '—' },
      { value: (row) => row.recipient_name || '—' },
      { value: (row) => row.purpose || '—' },
      { value: (row) => `${formatFullAmount(amountOf(row))} ${row.currency || 'KZT'}` },
    ])}</tbody>
  </table>

  <h2>Топ категорий</h2>
  <table>
    <thead><tr><th>Категория</th><th>Оборот</th><th>Операций</th><th>Доля оборота</th></tr></thead>
    <tbody>${renderDocRows(topCategories, [
      { value: (item) => item.name },
      { value: (item) => `${formatFullAmount(item.amount)} KZT` },
      { value: (item) => item.count },
      { value: (item) => `${Math.round((item.amount / Math.max(totalTurnover, 1)) * 100)}%` },
    ])}</tbody>
  </table>

  <h2>Анализ расходов</h2>
  <p>${topExpenseCategory ? `Наибольшая доля расходов приходится на категорию "${escapeDocText(topExpenseCategory.name)}" (${Math.round((topExpenseCategory.amount / Math.max(totalTurnover, 1)) * 100)}%).` : 'Расходные категории не определены.'}</p>
  <p>${regularPayments.length ? `Обнаружены регулярные платежи с повторяемостью: ${escapeDocText(regularPayments.map((item) => `${item.name} — ${item.count}`).join('; '))}.` : 'Регулярные платежи по повторяющимся суммам не выявлены.'}</p>
  <p>${charityRows.length ? `Благотворительность: ${charityRows.length} операций, сумма ${escapeDocText(formatFullAmount(charityRows.reduce((sum, row) => sum + amountOf(row), 0)))} KZT.` : 'Благотворительные платежи не обнаружены.'}</p>

  <h2>Анализ доходов</h2>
  <table>
    <tbody>
      <tr><th>Общее поступление</th><td>${escapeDocText(formatFullAmount(totalIncome))} KZT</td></tr>
      <tr><th>Пополнения через терминал / наличные</th><td>${escapeDocText(formatFullAmount(terminalIncome.reduce((sum, row) => sum + incomeOf(row), 0)))} KZT (${terminalIncome.length} операций)</td></tr>
      <tr><th>Переводы по счетам</th><td>${escapeDocText(formatFullAmount(transferIncome.reduce((sum, row) => sum + incomeOf(row), 0)))} KZT (${transferIncome.length} операций)</td></tr>
      <tr><th>Повторяемость доходов</th><td>${escapeDocText(groupTotals(incomeRows, (row) => `${monthLabel(row.date)} | ${Math.round(incomeOf(row) / 1000) * 1000}`).filter((item) => item.count >= 2).length ? 'Есть повторяющиеся поступления по месяцам/суммам' : 'Выраженная повторяемость доходов не выявлена')}</td></tr>
    </tbody>
  </table>
</body>
</html>`

      downloadDocFile(html, `${safeDocFileName(`Справка ${title}`)}.doc`)
    } catch (err) {
      window.alert(err?.message || 'Не удалось сформировать справку')
    } finally {
      setReportLoading(false)
    }
  }, [reportLoading])

  const closeEdgeModal = () => {
    setEdgeModal((prev) => ({ ...prev, open: false }))
  }

  useEffect(() => {
    let cancelled = false

    async function loadSeeds() {
      setLoadingSeeds(true)
      try {
        const res = await fetchTopCounterparties(12)
        if (cancelled) return
        const items = (res?.data || [])
          .filter((item) => item?.counterparty?.iin_bin)
          .map((item) => ({
            iinBin: item.counterparty.iin_bin,
            name: item.counterparty.name || item.counterparty.iin_bin,
            turnover: Number(item.total_turnover || 0),
            txCount: Number(item.transaction_count || 0),
            account: item.counterparty.account || '',
          }))

        setTopSeeds(items)
        if (externalFocusIin) {
          setManualIin(externalFocusIin)
          setManualName(externalFocusName || externalFocusIin)
          return
        }
        if (items[0]) {
          setManualIin(items[0].iinBin)
          void loadGraph(items[0])
        }
      } catch (err) {
        if (!cancelled) {
          setError(err?.message || 'Не удалось загрузить список контрагентов')
        }
      } finally {
        if (!cancelled) {
          setLoadingSeeds(false)
        }
      }
    }

    void loadSeeds()
    return () => {
      cancelled = true
    }
  }, [externalFocusIin, externalFocusName, loadGraph])

  useEffect(() => {
    if (!externalFocusIin) return

    setManualIin(externalFocusIin)
    setManualName(externalFocusName || externalFocusIin)
    void loadGraph(
      { iinBin: externalFocusIin, name: externalFocusName || externalFocusIin },
      { manualIin: externalFocusIin },
    )
  }, [externalFocusIin, externalFocusName, externalFocusRequestId, loadGraph])

  const elements = useMemo(() => buildElements(graphData), [graphData])

  useEffect(() => {
    if (!graphRef.current || !graphData) return undefined

    cyRef.current?.destroy()

    const cy = cytoscape({
      container: graphRef.current,
      elements,
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 650,
        fit: true,
        padding: 48,
        nodeRepulsion: 9500,
        idealEdgeLength: 140,
        edgeElasticity: 80,
        gravity: 0.4,
      },
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(shortLabel)',
            width: 'data(size)',
            height: 'data(size)',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 11,
            'font-weight': 700,
            color: isDark ? '#f4f4f5' : '#0f172a',
            'text-wrap': 'wrap',
            'text-max-width': 92,
            'overlay-opacity': 0,
            'border-width': (ele) => (ele.data('isCenter') ? 3 : 2),
            'border-color': (ele) => {
              if (ele.data('isCenter')) return isDark ? '#67e8f9' : '#0891b2'
              const level = ele.data('level')
              if (level === 1) return isDark ? '#818cf8' : '#6366f1'
              if (level === 2) return isDark ? '#a78bfa' : '#8b5cf6'
              return isDark ? '#94a3b8' : '#94a3b8'
            },
            'background-fill': 'linear-gradient',
            'background-gradient-stop-colors': (ele) => {
              if (ele.data('isCenter')) return isDark ? '#22d3ee #0f172a' : '#67e8f9 #e0f2fe'
              const level = ele.data('level')
              if (level === 1) return isDark ? '#818cf8 #1e1b4b' : '#c7d2fe #eef2ff'
              if (level === 2) return isDark ? '#a78bfa #312e81' : '#ddd6fe #f5f3ff'
              return isDark ? '#94a3b8 #18181b' : '#e2e8f0 #f8fafc'
            },
            'background-gradient-direction': 'to-bottom-right',
            'shadow-blur': 22,
            'shadow-color': (ele) => (ele.data('isCenter') ? '#22d3ee' : '#818cf8'),
            'shadow-opacity': isDark ? 0.28 : 0.14,
            'shadow-offset-x': 0,
            'shadow-offset-y': 10,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 'data(width)',
            'curve-style': 'bezier',
            'line-color': isDark ? '#475569' : '#cbd5e1',
            'target-arrow-color': isDark ? '#64748b' : '#94a3b8',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.9,
            opacity: 0.86,
            'overlay-opacity': 0,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#06b6d4',
            'border-width': 4,
            'shadow-opacity': 0.42,
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#06b6d4',
            'target-arrow-color': '#06b6d4',
            opacity: 1,
          },
        },
      ],
      wheelSensitivity: 0.18,
      userZoomingEnabled: true,
      userPanningEnabled: true,
    })

    const dragState = dragStateRef.current

    const resetDragState = () => {
      if (dragState.frameId != null) {
        cancelAnimationFrame(dragState.frameId)
      }
      if (dragState.inertiaFrameId != null) {
        cancelAnimationFrame(dragState.inertiaFrameId)
      }
      dragState.draggedId = null
      dragState.lastPosition = null
      dragState.pendingDelta = { x: 0, y: 0 }
      dragState.frameId = null
      dragState.inertiaFrameId = null
      dragState.affectedNodes = null
      dragState.weights = new Map()
      dragState.velocity = { x: 0, y: 0 }
      dragState.waterPhase = 0
      dragState.rippleStrength = 0
    }

    const scheduleInfluenceMove = () => {
      if (dragState.frameId != null) return

      dragState.frameId = requestAnimationFrame(() => {
        dragState.frameId = null
        const delta = dragState.pendingDelta
        dragState.pendingDelta = { x: 0, y: 0 }

        if (!dragState.affectedNodes || dragState.affectedNodes.empty()) {
          return
        }

        const velocityX = dragState.velocity.x
        const velocityY = dragState.velocity.y
        const smoothX = delta.x * 0.68 + velocityX * 0.08
        const smoothY = delta.y * 0.68 + velocityY * 0.08

        cy.batch(() => {
          dragState.affectedNodes.forEach((relatedNode) => {
            const weight = dragState.weights.get(relatedNode.id()) ?? 0
            if (weight <= 0) return
            const pos = relatedNode.position()
            relatedNode.position({
              x: pos.x + smoothX * weight,
              y: pos.y + smoothY * weight,
            })
          })
        })

        if (
          Math.abs(dragState.pendingDelta.x) > 0.001 ||
          Math.abs(dragState.pendingDelta.y) > 0.001
        ) {
          scheduleInfluenceMove()
        }
      })
    }

    const startInertia = () => {
      if (!dragState.affectedNodes || dragState.affectedNodes.empty()) return
      if (dragState.inertiaFrameId != null) {
        cancelAnimationFrame(dragState.inertiaFrameId)
      }

      const step = () => {
        const vx = dragState.velocity.x
        const vy = dragState.velocity.y
        const speed = Math.hypot(vx, vy)

        if (speed < 0.018 || !dragState.affectedNodes || dragState.affectedNodes.empty()) {
          dragState.inertiaFrameId = null
          dragState.affectedNodes = null
          dragState.weights = new Map()
          dragState.velocity = { x: 0, y: 0 }
          dragState.waterPhase = 0
          dragState.rippleStrength = 0
          pushGraphHistory(cy)
          return
        }

        cy.batch(() => {
          dragState.affectedNodes.forEach((relatedNode) => {
            const weight = dragState.weights.get(relatedNode.id()) ?? 0
            if (weight <= 0) return

            const pos = relatedNode.position()
            relatedNode.position({
              x: pos.x + vx * weight,
              y: pos.y + vy * weight,
            })
          })
        })

        dragState.velocity = {
          x: vx * 0.948,
          y: vy * 0.948,
        }
        dragState.inertiaFrameId = requestAnimationFrame(step)
      }

      dragState.inertiaFrameId = requestAnimationFrame(step)
    }

    const buildDragInfluence = (node) => {
      const firstHop = node.neighborhood().nodes().difference(node)
      const secondHop = firstHop.neighborhood().nodes().difference(firstHop).difference(node)

      const weights = new Map()
      firstHop.forEach((relatedNode) => {
        weights.set(relatedNode.id(), 0.42)
      })
      secondHop.forEach((relatedNode) => {
        if (!weights.has(relatedNode.id())) {
          weights.set(relatedNode.id(), 0.18)
        }
      })

      const prioritizedNodes = [...weights.keys()]
        .map((id) => cy.getElementById(id))
        .filter((relatedNode) => relatedNode && relatedNode.length > 0)
        .sort((a, b) => {
          const weightDelta = (weights.get(b.id()) ?? 0) - (weights.get(a.id()) ?? 0)
          if (weightDelta !== 0) return weightDelta
          return Number(b.data('totalTurnover') || 0) - Number(a.data('totalTurnover') || 0)
        })
        .slice(0, 40)

      const affectedNodes = cy.collection(prioritizedNodes)
      const affectedIds = new Set(prioritizedNodes.map((relatedNode) => relatedNode.id()))
      const limitedWeights = new Map(
        [...weights.entries()].filter(([id]) => affectedIds.has(id)),
      )

      return {
        affectedNodes,
        weights: limitedWeights,
      }
    }

    cy.on('tap', 'node', (event) => {
      const data = event.target.data()
      setSelectedEdge(null)
      setSelectedNode({
        id: data.id,
        label: data.label,
        iinBin: data.iinBin,
        level: data.level,
        totalTurnover: data.totalTurnover,
      })
    })

    cy.on('tap', 'edge', (event) => {
      const data = event.target.data()
      setSelectedNode(null)
      setSelectedEdge({
        source: data.source,
        target: data.target,
        amount: data.amount,
        txCount: data.txCount,
      })
    })

    cy.on('tap', (event) => {
      if (event.target === cy) {
        setSelectedNode(null)
        setSelectedEdge(null)
      }
    })

    cy.on('grab', 'node', (event) => {
      const grabbedNode = event.target
      if (dragState.inertiaFrameId != null) {
        cancelAnimationFrame(dragState.inertiaFrameId)
        dragState.inertiaFrameId = null
      }
      const { affectedNodes, weights } = buildDragInfluence(grabbedNode)
      dragState.draggedId = grabbedNode.id()
      dragState.lastPosition = { ...grabbedNode.position() }
      dragState.pendingDelta = { x: 0, y: 0 }
      dragState.affectedNodes = affectedNodes
      dragState.weights = weights
      dragState.velocity = { x: 0, y: 0 }
      dragState.waterPhase = 0
      dragState.rippleStrength = 0
    })

    cy.on('drag', 'node', (event) => {
      const draggedNode = event.target
      if (dragState.draggedId !== draggedNode.id()) return

      const currentPosition = draggedNode.position()
      const previousPosition = dragState.lastPosition
      if (!previousPosition) {
        dragState.lastPosition = { ...currentPosition }
        return
      }

      const dx = currentPosition.x - previousPosition.x
      const dy = currentPosition.y - previousPosition.y
      dragState.lastPosition = { ...currentPosition }

      if (Math.abs(dx) < 0.001 && Math.abs(dy) < 0.001) return

      dragState.pendingDelta.x += dx
      dragState.pendingDelta.y += dy
      dragState.velocity = {
        x: dragState.velocity.x * 0.82 + dx * 0.18,
        y: dragState.velocity.y * 0.82 + dy * 0.18,
      }
      scheduleInfluenceMove()
    })

    cy.on('free', 'node', (event) => {
      const draggedNode = event.target
      if (dragState.draggedId !== draggedNode.id()) {
        resetDragState()
        return
      }

      if (dragState.frameId != null) {
        cancelAnimationFrame(dragState.frameId)
        dragState.frameId = null
      }
      dragState.draggedId = null
      dragState.lastPosition = null
      dragState.pendingDelta = { x: 0, y: 0 }
      if (!dragState.affectedNodes || dragState.affectedNodes.empty()) {
        pushGraphHistory(cy)
        return
      }
      startInertia()
    })

    const scheduleViewportSnapshot = () => {
      if (applyingSnapshotRef.current) return
      if (viewportSnapshotTimerRef.current) {
        clearTimeout(viewportSnapshotTimerRef.current)
      }

      viewportSnapshotTimerRef.current = setTimeout(() => {
        pushGraphHistory(cy)
        viewportSnapshotTimerRef.current = null
      }, 220)
    }

    cy.on('pan zoom', scheduleViewportSnapshot)
    cy.one('layoutstop', () => {
      requestAnimationFrame(() => {
        const snapshot = buildGraphSnapshot(cy)
        if (!snapshot) return

        if (historyResetPendingRef.current) {
          historyResetPendingRef.current = false
          resetGraphHistory(snapshot)
          return
        }

        pushGraphHistory(cy)
      })
    })

    cyRef.current = cy

    return () => {
      if (viewportSnapshotTimerRef.current) {
        clearTimeout(viewportSnapshotTimerRef.current)
        viewportSnapshotTimerRef.current = null
      }
      resetDragState()
      cy.destroy()
      cyRef.current = null
    }
  }, [buildGraphSnapshot, elements, graphData, isDark, pushGraphHistory, resetGraphHistory])

  const selectedSummary = selectedNode
    ? {
        title: selectedNode.label,
        lines: [
          ['IIN/BIN', selectedNode.iinBin],
          ['Уровень', String(selectedNode.level ?? 0)],
          ['Оборот', formatCompactAmount(selectedNode.totalTurnover)],
        ],
      }
    : selectedEdge
      ? {
          title: 'Связь',
          lines: [
            ['От', selectedEdge.source],
            ['К', selectedEdge.target],
            ['Сумма', formatCompactAmount(selectedEdge.amount)],
            ['Транзакций', String(selectedEdge.txCount)],
          ],
        }
      : null

  const canGoBack = historyCursor > 0
  const canGoForward = historyCursor >= 0 && historyCursor < historySize - 1

  return (
    <section className="space-y-6">
      <div className={`rounded-[28px] border p-6 shadow-[0_18px_50px_rgba(15,23,42,0.06)] ${shellClass}`}>
        <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className={`mb-2 inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[10px] font-black uppercase tracking-[0.22em] ${chipClass}`}>
              <Waypoints className="h-3.5 w-3.5" />
              Network Graph
            </div>
            <h2 className={`text-2xl font-black tracking-tight ${headingText}`}>Связи по транзакциям</h2>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <label className={`rounded-2xl border px-4 py-3 text-sm ${panelClass}`}>
              <span className={`mb-1 block text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>IIN / BIN</span>
              <div className="flex items-center gap-2">
                <Search className={`h-4 w-4 ${mutedText}`} />
                <input
                  value={manualIin}
                  onChange={(event) => setManualIin(event.target.value)}
                  placeholder="Введите IIN/BIN"
                  className={`w-40 bg-transparent text-sm font-semibold outline-none ${headingText} placeholder:${mutedText}`}
                />
              </div>
            </label>

            <label className={`rounded-2xl border px-4 py-3 text-sm ${panelClass}`}>
              <span className={`mb-1 block text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Имя</span>
              <div className="flex items-center gap-2">
                <Search className={`h-4 w-4 ${mutedText}`} />
                <input
                  value={manualName}
                  onChange={(event) => setManualName(event.target.value)}
                  placeholder="Введите имя"
                  className={`w-48 bg-transparent text-sm font-semibold outline-none ${headingText} placeholder:${mutedText}`}
                />
              </div>
            </label>

            <label className={`rounded-2xl border px-4 py-3 text-sm ${panelClass}`}>
              <span className={`mb-1 block text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Depth</span>
              <select
                value={depth}
                onChange={(event) => setDepth(event.target.value)}
                className={`bg-transparent text-sm font-semibold outline-none ${headingText}`}
              >
                {['1', '2', '3', 'max'].map((value) => (
                  <option key={value} value={value} className="text-slate-900">
                    {value}
                  </option>
                ))}
              </select>
            </label>

            <label className={`rounded-2xl border px-4 py-3 text-sm ${panelClass}`}>
              <span className={`mb-1 block text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Neighbors</span>
              <select
                value={maxNeighbors}
                onChange={(event) => setMaxNeighbors(event.target.value)}
                className={`bg-transparent text-sm font-semibold outline-none ${headingText}`}
              >
                {['4', '6', '8', '10', '12', 'max'].map((value) => (
                  <option key={value} value={value} className="text-slate-900">
                    {value}
                  </option>
                ))}
              </select>
            </label>

            <button
              type="button"
              onClick={() => void handleBuildGraph()}
              className="inline-flex items-center gap-2 rounded-2xl bg-cyan-500 px-4 py-3 text-sm font-black text-white transition-all hover:scale-[1.02] hover:bg-cyan-400 active:scale-[0.99]"
            >
              {loadingGraph ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Построить граф
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[300px_minmax(0,1fr)_280px]">
        <aside className={`rounded-[28px] border p-5 ${shellClass}`}>
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className={`text-sm font-black uppercase tracking-[0.18em] ${headingText}`}>Топ контрагентов</h3>
              <p className={`mt-1 text-xs ${mutedText}`}>Быстрый старт для расследования</p>
            </div>
            {loadingSeeds && <Loader2 className={`h-4 w-4 animate-spin ${mutedText}`} />}
          </div>

          <div className="space-y-2 max-h-[680px] overflow-y-auto pr-1 custom-scrollbar">
            {topSeeds.map((item) => {
              const active = focusNode?.iinBin === item.iinBin
              return (
                <button
                  key={item.iinBin}
                  type="button"
                  onClick={() => void loadGraph(item)}
                  className={`w-full rounded-2xl border px-4 py-3 text-left transition-all ${
                    active
                      ? isDark
                        ? 'border-cyan-400/40 bg-cyan-400/10'
                        : 'border-cyan-300 bg-cyan-50'
                      : chipClass
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className={`truncate text-sm font-bold ${headingText}`}>{item.name}</div>
                      <div className={`mt-1 truncate text-[11px] ${mutedText}`}>{item.iinBin}</div>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className={`text-xs font-black ${isDark ? 'text-cyan-200' : 'text-cyan-700'}`}>
                        {formatCompactAmount(item.turnover)}
                      </div>
                      <div className={`mt-1 text-[10px] font-bold ${mutedText}`}>{item.txCount} tx</div>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        </aside>

        <div
          ref={graphShellRef}
          className={
            isFullscreen
              ? `${isDark ? 'bg-[#0b0d14]' : 'bg-slate-50'} h-full w-full p-5`
              : `rounded-[28px] border p-4 ${shellClass}`
          }
        >
          <div className={`mb-3 flex flex-wrap items-center justify-between gap-3 rounded-2xl border px-4 py-3 ${panelClass}`}>
            <div>
              <div className={`text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Center node</div>
              <div className={`mt-1 text-sm font-bold ${headingText}`}>{focusNode?.label || '—'}</div>
            </div>
            <div className="flex items-center gap-2">
              <div className={`text-xs ${mutedText}`}>
                {(graphData?.nodes || []).length} узлов · {(graphData?.edges || []).length} связей
              </div>
            </div>
          </div>

          {error && (
            <div className={`mb-3 rounded-2xl border px-4 py-3 text-sm ${isDark ? 'border-rose-500/20 bg-rose-500/10 text-rose-200' : 'border-rose-200 bg-rose-50 text-rose-600'}`}>
              {error}
            </div>
          )}

          <div
            className={`relative overflow-hidden rounded-[24px] border ${panelClass} ${
              isFullscreen ? 'min-h-[calc(100vh-136px)]' : 'min-h-[680px]'
            }`}
          >
            <div className="absolute right-4 top-4 z-20 flex items-center gap-2">
              <button
                type="button"
                onClick={() => navigateHistory(-1)}
                disabled={!canGoBack}
                className={`inline-flex h-10 w-10 items-center justify-center rounded-2xl border transition-all ${
                  canGoBack
                    ? `hover:scale-[1.02] ${chipClass}`
                    : isDark
                      ? 'cursor-not-allowed border-zinc-900 bg-zinc-950/70 text-zinc-700'
                      : 'cursor-not-allowed border-slate-200 bg-white/85 text-slate-300'
                }`}
                aria-label="Предыдущее состояние графа"
                title="Назад"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={() => navigateHistory(1)}
                disabled={!canGoForward}
                className={`inline-flex h-10 w-10 items-center justify-center rounded-2xl border transition-all ${
                  canGoForward
                    ? `hover:scale-[1.02] ${chipClass}`
                    : isDark
                      ? 'cursor-not-allowed border-zinc-900 bg-zinc-950/70 text-zinc-700'
                      : 'cursor-not-allowed border-slate-200 bg-white/85 text-slate-300'
                }`}
                aria-label="Следующее состояние графа"
                title="Вперёд"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={centerGraph}
                className={`inline-flex h-10 w-10 items-center justify-center rounded-2xl border transition-all hover:scale-[1.02] ${chipClass}`}
                aria-label="Центрировать граф"
                title="Центрировать граф"
              >
                <LocateFixed className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={() => void toggleFullscreen()}
                className={`inline-flex h-10 w-10 items-center justify-center rounded-2xl border transition-all hover:scale-[1.02] ${chipClass}`}
                aria-label={isFullscreen ? 'Выйти из полноэкранного режима' : 'Открыть полноэкранный режим'}
                title={isFullscreen ? 'Свернуть граф' : 'Полный экран'}
              >
                {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
              </button>
            </div>

            {loadingGraph && (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-white/70 dark:bg-black/40 backdrop-blur-sm">
                <div className={`flex items-center gap-3 rounded-2xl border px-4 py-3 ${panelClass}`}>
                  <Loader2 className="h-4 w-4 animate-spin text-cyan-500" />
                  <span className={`text-sm font-semibold ${headingText}`}>Строю граф связей…</span>
                </div>
              </div>
            )}

            <div
              ref={graphRef}
              className={isFullscreen ? 'h-[calc(100vh-136px)] w-full' : 'h-[680px] w-full'}
            />
          </div>
        </div>

        <aside className={`rounded-[28px] border p-5 ${shellClass}`}>
          <div className="mb-4">
            <h3 className={`text-sm font-black uppercase tracking-[0.18em] ${headingText}`}>Детали</h3>
            <p className={`mt-1 text-xs ${mutedText}`}>Кликни по узлу или связи, чтобы посмотреть контекст.</p>
          </div>

          {selectedSummary ? (
            <div className={`space-y-4 rounded-[24px] border p-4 ${panelClass}`}>
              <div>
                <div className={`text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>
                  {selectedNode ? 'Контрагент' : 'Связь'}
                </div>
                <div className={`mt-2 text-lg font-black leading-tight ${headingText}`}>{selectedSummary.title}</div>
              </div>

              <div className="space-y-2">
                {selectedSummary.lines.map(([label, value], idx) => {
                  const isTransactionsRow = Boolean(selectedEdge) && idx === selectedSummary.lines.length - 1
                  const isTurnoverRow = Boolean(selectedNode) && label === 'Оборот'

                  if (isTransactionsRow || isTurnoverRow) {
                    return (
                      <button
                        key={label}
                        type="button"
                        onClick={() =>
                          void (isTransactionsRow
                            ? openEdgeTransactions(selectedEdge)
                            : openNodeTransactions(selectedNode))
                        }
                        className={`flex w-full items-center justify-between gap-3 rounded-2xl border px-3 py-2 text-left transition-all hover:scale-[1.01] ${subtleBg} ${isDark ? 'border-cyan-500/30 hover:border-cyan-400/50 hover:bg-cyan-500/10' : 'border-cyan-200 hover:border-cyan-300 hover:bg-cyan-50'}`}
                      >
                        <span className={`text-[10px] font-black uppercase tracking-[0.16em] ${mutedText}`}>{label}</span>
                        <span className={`text-right text-sm font-bold ${headingText}`}>{value}</span>
                      </button>
                    )
                  }

                  return (
                    <div
                      key={label}
                      className={`flex items-center justify-between gap-3 rounded-2xl border px-3 py-2 ${subtleBg} ${isDark ? 'border-zinc-800' : 'border-slate-200'}`}
                    >
                      <span className={`text-[10px] font-black uppercase tracking-[0.16em] ${mutedText}`}>{label}</span>
                      <span className={`text-right text-sm font-bold ${headingText}`}>{value}</span>
                    </div>
                  )
                })}
              </div>

              {selectedNode && (
                <button
                  type="button"
                  onClick={() => void downloadNodeReport(selectedNode)}
                  disabled={reportLoading}
                  className={`flex w-full items-center justify-center gap-2 rounded-2xl border px-4 py-3 text-sm font-black transition-all hover:scale-[1.02] disabled:cursor-wait disabled:opacity-60 ${
                    isDark
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/15'
                      : 'border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100'
                  }`}
                >
                  {reportLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                  Справка
                </button>
              )}

              {selectedNode && selectedNode.iinBin !== focusNode?.iinBin && (
                <button
                  type="button"
                  onClick={() => void loadGraph({ iinBin: selectedNode.iinBin, name: selectedNode.label })}
                  className="w-full rounded-2xl bg-indigo-500 px-4 py-3 text-sm font-black text-white transition-all hover:scale-[1.02] hover:bg-indigo-400 active:scale-[0.99]"
                >
                  Фокус на этом узле
                </button>
              )}
            </div>
          ) : (
            <div className={`rounded-[24px] border border-dashed p-5 text-sm ${isDark ? 'border-zinc-800 text-zinc-500' : 'border-slate-200 text-slate-400'}`}>
              Выбери контрагента слева или кликни по элементу на графе.
            </div>
          )}

          <div className={`mt-4 rounded-[24px] border p-4 ${panelClass}`}>
            <div className={`text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Как читать граф</div>
            <ul className={`mt-3 space-y-2 text-sm ${mutedText}`}>
              <li>Крупнее круг — больше совокупный оборот.</li>
              <li>Яркий центр — текущий фокус расследования.</li>
              <li>Толще линия — больше сумма между узлами.</li>
            </ul>
          </div>
        </aside>
      </div>

      {edgeModal.open && (
        <div className="fixed inset-0 z-[120]">
          <div className="absolute inset-0 bg-black/60" onClick={closeEdgeModal}></div>
          <div className="absolute inset-0 flex items-center justify-center p-6">
            <div className={`relative z-10 flex max-h-[85vh] w-full max-w-6xl flex-col overflow-hidden rounded-[28px] border ${shellClass}`}>
              <div className={`flex items-center justify-between border-b px-6 py-5 ${isDark ? 'border-zinc-800' : 'border-slate-200'}`}>
                <div>
                  <h3 className={`text-lg font-black ${headingText}`}>Транзакции между узлами</h3>
                  <p className={`mt-1 text-sm ${mutedText}`}>{edgeModal.title} · Найдено: {edgeModal.total}</p>
                </div>
                <div className="flex items-center gap-2">
                  {edgeModal.rows.length > 0 && !edgeModal.loading && !edgeModal.error && (
                    <button
                      type="button"
                      onClick={exportEdgeModalExcel}
                      className={`inline-flex items-center gap-2 rounded-2xl border px-4 py-2 text-sm font-bold transition-all ${
                        isDark
                          ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-100 hover:border-emerald-300/40 hover:bg-emerald-400/15'
                          : 'border-emerald-200 bg-emerald-50 text-emerald-700 hover:border-emerald-300 hover:bg-emerald-100'
                      }`}
                    >
                      <FileSpreadsheet className="h-4 w-4" />
                      Excel
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={closeEdgeModal}
                    className={`rounded-2xl border px-4 py-2 text-sm font-bold transition-all ${chipClass}`}
                  >
                    Закрыть
                  </button>
                </div>
              </div>

              <div className="min-h-0 flex-1 overflow-auto p-5 custom-scrollbar">
                {edgeModal.loading && (
                  <div className={`flex items-center gap-3 rounded-2xl border px-4 py-3 ${panelClass}`}>
                    <Loader2 className="h-4 w-4 animate-spin text-cyan-500" />
                    <span className={`text-sm font-semibold ${headingText}`}>Загружаю список транзакций…</span>
                  </div>
                )}

                {!edgeModal.loading && edgeModal.error && (
                  <div className={`rounded-2xl border px-4 py-3 text-sm ${isDark ? 'border-rose-500/20 bg-rose-500/10 text-rose-200' : 'border-rose-200 bg-rose-50 text-rose-600'}`}>
                    {edgeModal.error}
                  </div>
                )}

                {!edgeModal.loading && !edgeModal.error && edgeModal.rows.length === 0 && (
                  <div className={`rounded-2xl border border-dashed px-4 py-6 text-sm ${isDark ? 'border-zinc-800 text-zinc-500' : 'border-slate-200 text-slate-400'}`}>
                    {edgeModal.emptyText}
                  </div>
                )}

                {!edgeModal.loading && !edgeModal.error && edgeModal.rows.length > 0 && (
                  <div className={`overflow-hidden rounded-[24px] border ${isDark ? 'border-zinc-800' : 'border-slate-200'}`}>
                    <table className="min-w-full text-left">
                      <thead className={isDark ? 'bg-zinc-950/80' : 'bg-slate-50'}>
                        <tr>
                          <th className={`px-4 py-3 text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Дата</th>
                          <th className={`px-4 py-3 text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Отправитель</th>
                          <th className={`px-4 py-3 text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Получатель</th>
                          <th className={`px-4 py-3 text-[10px] font-black uppercase tracking-[0.18em] ${mutedText}`}>Назначение</th>
                          <th className={`px-4 py-3 text-[10px] font-black uppercase tracking-[0.18em] text-right ${mutedText}`}>Сумма</th>
                        </tr>
                      </thead>
                      <tbody>
                        {edgeModal.rows.map((row) => (
                          <tr key={row.id} className={isDark ? 'border-t border-zinc-800' : 'border-t border-slate-200'}>
                            <td className={`px-4 py-3 align-top text-sm ${headingText}`}>{row.date || '—'}</td>
                            <td className={`px-4 py-3 align-top text-sm ${headingText}`}>{row.sender_name || '—'}</td>
                            <td className={`px-4 py-3 align-top text-sm ${headingText}`}>{row.recipient_name || '—'}</td>
                            <td className={`px-4 py-3 align-top text-sm ${mutedText}`}>{row.purpose || '—'}</td>
                            <td className={`px-4 py-3 align-top text-right text-sm font-bold ${headingText}`}>
                              {formatFullAmount(row.amount_tenge || row.debit || row.credit)} {row.currency || 'KZT'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default NetworkGraph
