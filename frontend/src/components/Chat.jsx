import React, { useEffect, useRef, useState } from 'react'
import { Download, ArrowRight, Sparkles, Loader2 } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { queryChatStream } from '../services/api'
import { autoFitWorksheetColumns } from '../utils/xlsx'

const SUGGESTIONS = [
  'Топ 5 расходов за 2024',
  'Покажи крупные поступления за 2024',
  'Найди переводы по займам',
]

const HIDDEN_RESULT_COLUMNS = new Set(['tx_id'])
const MAX_VISIBLE_RESULT_ROWS = 10
const RESULT_VIEWPORT_HEIGHT = 44 * MAX_VISIBLE_RESULT_ROWS + 52

const RESULT_COLUMN_LABELS = {
  operation_date: 'Дата',
  payer_name: 'Отправитель',
  receiver_name: 'Получатель',
  purpose_text: 'Назначение',
  amount_kzt: 'Сумма',
}

function makeId(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function formatValue(value) {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'number') return value.toLocaleString('ru-RU')
  return String(value)
}

function getVisibleColumns(rows) {
  return Object.keys(rows?.[0] || {}).filter((column) => !HIDDEN_RESULT_COLUMNS.has(column))
}

function buildExportRows(rows, columns) {
  return rows.map((row) =>
    Object.fromEntries(
      columns.map((column) => [RESULT_COLUMN_LABELS[column] || column, row[column] ?? ''])
    )
  )
}

function makeExportFileName() {
  const ts = new Date().toISOString().replace(/[:.]/g, '-')
  return `chat-results-${ts}.xlsx`
}

function ResultPreview({ rows, sql }) {
  if (!rows?.length && !sql) return null

  const columns = rows?.length ? getVisibleColumns(rows) : []

  async function handleDownload() {
    const XLSX = await import('xlsx')
    const workbook = XLSX.utils.book_new()
    const exportRows = buildExportRows(rows, columns)
    const worksheet = XLSX.utils.json_to_sheet(exportRows)
    autoFitWorksheetColumns(worksheet, exportRows, { maxWidth: 70 })

    XLSX.utils.book_append_sheet(workbook, worksheet, 'Chat Results')
    XLSX.writeFile(workbook, makeExportFileName())
  }

  return (
    <div className="mt-4 overflow-hidden rounded-2xl border border-slate-100/80 bg-white/90 shadow-sm dark:border-zinc-800/70 dark:bg-zinc-950/70">
      {sql && (
        <details className={`group ${rows?.length ? 'border-b border-slate-100/80 dark:border-zinc-800/60' : ''}`}>
          <summary className="flex cursor-pointer select-none items-center gap-2 px-4 py-3 text-[10px] font-black uppercase tracking-widest text-slate-500 transition-colors hover:bg-slate-50/50 hover:text-indigo-500 dark:bg-zinc-900/40 dark:text-zinc-500 dark:hover:bg-zinc-900/60 dark:hover:text-indigo-400">
            <div className="h-1.5 w-1.5 rounded-full bg-slate-300 transition-colors group-hover:bg-indigo-500 dark:bg-zinc-700" />
            SQL
            <span className="ml-auto text-[10px] text-slate-400 opacity-0 transition-opacity group-hover:opacity-100 dark:text-zinc-600">
              развернуть ↓
            </span>
          </summary>
          <div className="border-t border-slate-100/80 bg-slate-50/30 p-4 font-mono text-[11px] text-zinc-600 dark:border-zinc-800/60 dark:bg-zinc-950/50 dark:text-zinc-400">
            <pre className="whitespace-pre-wrap">{sql}</pre>
          </div>
        </details>
      )}

      {rows?.length > 0 && (
        <>
          <div className="flex items-center justify-between gap-3 border-b border-slate-100/80 bg-slate-50/60 px-4 py-2 dark:border-zinc-800/60 dark:bg-zinc-900/40">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-zinc-500">
              Найдено {rows.length} строк
            </div>
            <button
              type="button"
              onClick={handleDownload}
              className="flex items-center gap-1.5 rounded-lg border border-black/10 bg-white px-3 py-1 text-[10px] font-bold text-slate-600 transition-all hover:bg-slate-50 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400"
            >
              <Download className="h-3 w-3" />
              CSV
            </button>
          </div>

          <div className="custom-scrollbar overflow-x-auto">
            <div style={{ maxHeight: `${RESULT_VIEWPORT_HEIGHT}px` }}>
              <table className="min-w-full border-collapse text-sm">
                <thead className="sticky top-0 z-10 bg-slate-100/80 dark:bg-zinc-900/85">
                  <tr>
                    {columns.map((column) => (
                      <th
                        key={column}
                        className="whitespace-nowrap border-b border-slate-100 px-4 py-2.5 text-left text-[11px] font-black uppercase tracking-widest text-slate-500 dark:border-zinc-800 dark:text-zinc-400"
                      >
                        {RESULT_COLUMN_LABELS[column] || column}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-zinc-800/60">
                  {rows.map((row, index) => (
                    <tr
                      key={index}
                      className="transition-colors even:bg-slate-50/30 hover:bg-slate-50/70 dark:even:bg-zinc-900/15 dark:hover:bg-zinc-900/30"
                    >
                      {columns.map((column) => (
                        <td
                          key={column}
                          className="px-4 py-2.5 align-top text-[12px] font-medium text-slate-600 dark:text-zinc-300"
                        >
                          {formatValue(row[column])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function Chat() {
  const textareaRef = useRef(null)
  const [input, setInput] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [messages, setMessages] = useState([
    {
      id: makeId('assistant'),
      role: 'assistant',
      text: 'AFM Chat готов. Задай вопрос по транзакциям.',
      rows: [],
    },
  ])

  useEffect(() => {
    window.scrollTo({
      top: document.body.scrollHeight,
      behavior: 'smooth',
    })
  }, [messages, isSending])

  async function submitQuestion(rawQuestion) {
    const question = rawQuestion.trim()
    if (!question || isSending) return

    setMessages((prev) => [...prev, { id: makeId('user'), role: 'user', text: question }])
    setInput('')
    setIsSending(true)

    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }

    const botMsgId = makeId('assistant')
    setMessages((prev) => [...prev, { 
      id: botMsgId, 
      role: 'assistant', 
      text: 'Инициализация...', 
      rows: [], 
      sql: '',
      isStreaming: true 
    }])

    try {
      let fullSummary = ''
      let hasSummaryStarted = false

      await queryChatStream(question, (event) => {
        setMessages((prev) =>
          prev.map((message) => {
            if (message.id !== botMsgId) return message

            switch (event.event) {
              case 'status':
                return hasSummaryStarted ? message : { ...message, text: event.data }
              
              case 'sql':
                return { ...message, sql: event.data }
              
              case 'rows':
                return { ...message, rows: event.data }
              
              case 'summary_chunk':
                if (!hasSummaryStarted) {
                  hasSummaryStarted = true
                  fullSummary = event.data
                } else {
                  fullSummary += event.data
                }
                return { ...message, text: fullSummary }
              
              case 'done':
                return { 
                  ...message, 
                  ...event.data, 
                  text: event.data.ai_summary || fullSummary,
                  isStreaming: false 
                }
                
              case 'error':
                return { ...message, text: `Ошибка: ${event.error}`, isStreaming: false }
              
              default:
                return message
            }
          })
        )
      })
    } catch (error) {
      setMessages((prev) =>
        prev.map((message) =>
          message.id === botMsgId
            ? { ...message, text: error.message || 'Ошибка соединения', isStreaming: false }
            : message
        )
      )
    } finally {
      setIsSending(false)
    }
  }

  function handleSubmit(event) {
    event.preventDefault()
    submitQuestion(input)
  }

  function handleKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      submitQuestion(input)
    }
  }

  function autoResize(event) {
    event.target.style.height = 'auto'
    event.target.style.height = `${Math.min(event.target.scrollHeight, 160)}px`
  }

  return (
    <div className="min-h-screen max-w-5xl mx-auto bg-transparent pb-44">
      {messages.length <= 1 ? (
        <div className="flex min-h-[70vh] flex-col items-center justify-center px-6 text-center animate-in fade-in duration-700">
          <div className="mb-8 rounded-2xl bg-indigo-500/10 p-4">
            <Sparkles className="h-8 w-8 text-indigo-500" />
          </div>

          <h1 className="mb-4 text-3xl font-black tracking-tight text-slate-800 dark:text-zinc-100">
            AFM AI Assistant
          </h1>
          <p className="mb-10 max-w-sm text-sm font-medium text-slate-400">
            Задайте любой вопрос по транзакциям, расходам или поступлениям за 2024 год.
          </p>

          <div className="mb-8 w-full max-w-2xl">
            <form
              onSubmit={handleSubmit}
              className="group relative flex items-center gap-2 rounded-[30px] bg-white/85 p-2 shadow-[0_18px_40px_rgba(15,23,42,0.08)] backdrop-blur-md transition-all dark:bg-zinc-950/70"
            >
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={handleKeyDown}
                onInput={autoResize}
                rows={1}
                placeholder="Задайте вопрос..."
                className="min-h-[44px] max-h-40 flex-1 resize-none bg-transparent px-4 py-3 text-[14px] font-medium text-slate-900 outline-none placeholder:text-slate-400 dark:text-zinc-100 dark:placeholder:text-zinc-600"
              />

              <button
                type="submit"
                disabled={!input.trim() || isSending}
                className="flex h-[40px] w-[40px] shrink-0 items-center justify-center rounded-full bg-indigo-500 text-white shadow-lg shadow-indigo-500/20 transition-all hover:bg-indigo-600 active:scale-95 disabled:grayscale disabled:opacity-30"
              >
                {isSending ? (
                  <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                ) : (
                  <ArrowRight className="h-4 w-4" />
                )}
              </button>
            </form>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3">
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => submitQuestion(suggestion)}
                disabled={isSending}
                className="rounded-lg border border-black/10 bg-white px-4 py-2 text-[11px] font-bold text-slate-600 shadow-sm transition-all hover:scale-[1.02] hover:border-black/20 hover:bg-[#f9f9f9] disabled:opacity-50 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400"
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-10 px-6 py-12 animate-in slide-in-from-bottom-4 duration-500">
          <div className="mb-8 flex items-center justify-between border-b border-slate-100/80 pb-6 dark:border-zinc-800/70">
            <h2 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400">
              Conversation History
            </h2>
            <button
              onClick={() => setMessages([messages[0]])}
              className="rounded-lg border border-black/10 bg-white px-3 py-1.5 text-[10px] font-bold text-slate-600 transition-all hover:bg-[#f9f9f9] dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400"
            >
              Restart
            </button>
          </div>

          {messages.slice(1).map((message) => (
            <div
              key={message.id}
              className={`flex flex-col gap-3 ${message.role === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div className={`w-full ${message.role === 'user' ? 'flex justify-end' : ''}`}>
                <div
                  className={`space-y-4 text-[13px] leading-relaxed ${message.role === 'user'
                    ? 'max-w-[78%] rounded-[26px] bg-indigo-500 px-5 py-4 text-white shadow-[0_18px_34px_rgba(99,102,241,0.24)]'
                    : 'max-w-[88%] text-slate-600 dark:text-zinc-300'
                    }`}
                >
                  {message.role === 'user' ? (
                    <p className="whitespace-pre-wrap">{message.text}</p>
                  ) : (
                    <div className="space-y-2">
                      {message.isStreaming && !message.text.includes(' ') && !message.text.includes('.') ? (
                        <div className="flex items-center gap-2 text-indigo-500 font-bold italic animate-pulse">
                          <Loader2 className="h-3 w-3 animate-spin" />
                          {message.text}
                        </div>
                      ) : (
                        <ReactMarkdown
                          components={{
                            p: ({ node, ...props }) => { void node; return <p className="mb-2 whitespace-pre-wrap" {...props} /> },
                            ul: ({ node, ...props }) => { void node; return <ul className="list-disc pl-4 mb-2 space-y-1" {...props} /> },
                            ol: ({ node, ...props }) => { void node; return <ol className="list-decimal pl-4 mb-2 space-y-1" {...props} /> },
                            li: ({ node, ...props }) => { void node; return <li className="" {...props} /> },
                            strong: ({ node, ...props }) => { void node; return <strong className="font-bold text-slate-800 dark:text-zinc-200" {...props} /> },
                          }}
                        >
                          {message.text}
                        </ReactMarkdown>
                      )}
                    </div>
                  )}
                  {message.role !== 'user' && <ResultPreview rows={message.rows} sql={message.sql} />}
                </div>
              </div>
            </div>
          ))}

          {isSending && (
            <div className="flex items-center gap-3">
              <span className="flex gap-1">
                <span className="h-1 w-1 animate-bounce rounded-full bg-indigo-400 [animation-delay:-0.3s]"></span>
                <span className="h-1 w-1 animate-bounce rounded-full bg-indigo-400 [animation-delay:-0.15s]"></span>
                <span className="h-1 w-1 animate-bounce rounded-full bg-indigo-400"></span>
              </span>
              <span className="text-[9px] font-black uppercase tracking-widest text-slate-400">
                Формирование ответа...
              </span>
            </div>
          )}
        </div>
      )}

      {messages.length > 1 && (
        <div className="fixed bottom-0 left-0 right-0 z-30">
          <div className="mx-auto max-w-3xl px-6 pb-10">
            <div className="p-4">
              <div className="no-scrollbar mb-4 flex flex-wrap gap-2 overflow-x-auto px-2">
                {SUGGESTIONS.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    onClick={() => submitQuestion(suggestion)}
                    disabled={isSending}
                    className="whitespace-nowrap rounded-lg border border-black/10 bg-white px-3 py-1.5 text-[10px] font-bold text-slate-600 shadow-sm transition-all hover:bg-[#f9f9f9] disabled:opacity-50 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>

              <form
                onSubmit={handleSubmit}
                className="group relative flex items-center gap-2 rounded-[30px] p-1.5 transition-all"
              >
                <textarea
                  ref={textareaRef}
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  onKeyDown={handleKeyDown}
                  onInput={autoResize}
                  rows={1}
                  placeholder="Задайте вопрос..."
                  className="min-h-[44px] max-h-40 flex-1 resize-none rounded-[26px] bg-white/88 px-4 py-3 text-[14px] font-medium text-slate-900 outline-none shadow-[0_10px_24px_rgba(15,23,42,0.06)] ring-1 ring-black/6 placeholder:text-slate-400 dark:bg-zinc-950/70 dark:text-zinc-100 dark:ring-white/10 dark:placeholder:text-zinc-600"
                />

                <button
                  type="submit"
                  disabled={!input.trim() || isSending}
                  className="flex h-[40px] w-[40px] shrink-0 items-center justify-center rounded-full bg-indigo-500 text-white shadow-lg shadow-indigo-500/20 transition-all hover:bg-indigo-600 active:scale-95 disabled:grayscale disabled:opacity-30"
                >
                  {isSending ? (
                    <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  ) : (
                    <ArrowRight className="h-4 w-4" />
                  )}
                </button>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Chat
