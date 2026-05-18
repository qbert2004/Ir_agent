import React, { useEffect, useRef, useState } from 'react'
import { queryChatStream } from '../services/api'

const SUGGESTIONS = [
  'Топ 5 расходов за 2024',
  'Покажи крупные поступления за 2024',
  'Найди переводы по займам',
]

const HIDDEN_RESULT_COLUMNS = new Set(['tx_id'])
const RESULT_COLUMN_LABELS = {
  operation_date: 'Дата',
  operation_ts: 'Дата',
  date: 'Дата',
  payer_name: 'Отправитель',
  sender_name: 'Отправитель',
  receiver_name: 'Получатель',
  recipient_name: 'Получатель',
  purpose_text: 'Назначение',
  purpose: 'Назначение',
  amount_kzt: 'Сумма',
  amount_tenge: 'Сумма',
  amount_credit: 'Поступление',
  amount_debit: 'Расход',
  direction: 'Направление',
  currency: 'Валюта',
  payer_bank: 'Банк отправителя',
  receiver_bank: 'Банк получателя',
}

function makeId(prefix) {
  if (globalThis.crypto?.randomUUID) {
    return `${prefix}-${globalThis.crypto.randomUUID()}`
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function formatValue(value) {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'number') return value.toLocaleString('ru-RU')
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет'
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }
  return String(value)
}

function getVisibleColumns(rows) {
  return Object.keys(rows?.[0] || {}).filter((column) => !HIDDEN_RESULT_COLUMNS.has(column))
}

function getColumnLabel(column) {
  return RESULT_COLUMN_LABELS[column] || column
}

function ResultPreview({ rows, theme }) {
  if (!rows?.length) return null

  const columns = getVisibleColumns(rows)
  const isDark = theme === 'dark'
  if (!columns.length) return null

  return (
    <div className={`mt-3 overflow-hidden rounded-2xl border ${isDark ? 'border-cyan-400/10 bg-slate-950/60' : 'border-sky-200 bg-white/95'}`}>
      <div className="max-h-80 overflow-auto chat-scrollbar">
        <table className="min-w-full text-xs">
          <thead className={isDark ? 'bg-slate-900/90 text-slate-300' : 'bg-sky-50 text-slate-600'}>
            <tr>
              {columns.map((column) => (
                <th key={column} className="whitespace-nowrap px-3 py-2 text-left font-semibold">
                  {getColumnLabel(column)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className={isDark ? 'divide-y divide-slate-800 text-slate-100' : 'divide-y divide-slate-100 text-slate-800'}>
            {rows.map((row, index) => (
              <tr key={`preview-${index}`}>
                {columns.map((column) => (
                  <td key={`${column}-${index}`} className="whitespace-nowrap px-3 py-2 align-top">
                    {formatValue(row[column])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </div>
  )
}

function ResultsModal({ modal, theme, onClose }) {
  if (!modal.open) return null

  const isDark = theme === 'dark'
  const columns = getVisibleColumns(modal.rows)

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose}></div>
      <div
        className={`relative z-10 w-full max-w-6xl max-h-[85vh] overflow-hidden rounded-xl border ${
          isDark ? 'bg-slate-900 border-slate-700' : 'bg-white border-sky-100'
        }`}
      >
        <div className={`px-5 py-4 border-b flex items-center justify-between ${isDark ? 'border-slate-700' : 'border-sky-100'}`}>
          <div>
            <h3 className={`text-base font-semibold ${isDark ? 'text-white' : 'text-slate-900'}`}>{modal.title}</h3>
            <p className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Найдено: {modal.rows.length}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className={`px-3 py-1.5 rounded-md text-xs ${isDark ? 'bg-slate-800 text-slate-300 hover:bg-slate-700' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
          >
            Закрыть
          </button>
        </div>

        <div className="p-4 overflow-auto max-h-[65vh] chat-scrollbar">
          {!modal.rows.length || !columns.length ? (
            <div className={`text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Нет строк для отображения</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className={`${isDark ? 'text-slate-400 border-slate-700' : 'text-slate-500 border-slate-200'} border-b`}>
                  {columns.map((column) => (
                    <th key={column} className="text-left py-2 pr-3 whitespace-nowrap">
                      {getColumnLabel(column)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {modal.rows.map((row, index) => (
                  <tr
                    key={row.tx_id || row.id || `chat-row-${index}`}
                    className={`${isDark ? 'border-slate-800 text-slate-200' : 'border-slate-100 text-slate-800'} border-b`}
                  >
                    {columns.map((column) => (
                      <td key={`${column}-${index}`} className="py-2 pr-3 align-top whitespace-nowrap">
                        {formatValue(row[column])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

function AssistantMessage({ message, theme, onOpenResults }) {
  const isDark = theme === 'dark'

  return (
    <div
      className={`max-w-[92%] rounded-[24px] border px-4 py-3 shadow-lg ${
        message.error
          ? isDark
            ? 'border-rose-500/30 bg-rose-950/80 text-rose-100'
            : 'border-rose-200 bg-rose-50 text-rose-900'
          : isDark
            ? 'border-cyan-400/10 bg-slate-900/95 text-slate-100'
            : 'border-sky-100 bg-white text-slate-800'
      }`}
    >
      <p className="whitespace-pre-wrap text-sm leading-6">{message.text}</p>

      {message.sql && (
        <details className="group mt-3">
          <summary className={`cursor-pointer text-xs font-medium ${isDark ? 'text-cyan-300' : 'text-sky-700'}`}>
            Показать SQL
          </summary>
          <pre className={`chat-scrollbar mt-2 overflow-x-auto rounded-2xl p-3 text-[11px] leading-5 ${
            isDark ? 'bg-slate-950/80 text-slate-200' : 'bg-slate-50 text-slate-700'
          }`}>
            <code>{message.sql}</code>
          </pre>
        </details>
      )}

      <ResultPreview rows={message.rows} theme={theme} />

      {message.rows?.length > 0 && (
        <div className="mt-3 flex justify-end">
          <button
            type="button"
            onClick={() => onOpenResults(message)}
            className={`rounded-full px-3 py-1.5 text-xs transition-colors ${
              isDark
                ? 'bg-slate-800 text-slate-200 hover:bg-slate-700'
                : 'bg-sky-50 text-sky-700 hover:bg-sky-100'
            }`}
          >
            Открыть в окне
          </button>
        </div>
      )}
    </div>
  )
}

function ChatWidget({ theme }) {
  const [isOpen, setIsOpen] = useState(false)
  const [input, setInput] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [resultsModal, setResultsModal] = useState({
    open: false,
    title: 'Найденные строки',
    rows: [],
  })
  const [messages, setMessages] = useState([
    {
      id: makeId('assistant'),
      role: 'assistant',
      text: 'AFM Chat готов. Задай вопрос по транзакциям, и я попробую собрать SQL и вернуть результат.',
      rows: [],
      sql: '',
      error: '',
    },
  ])

  const scrollRef = useRef(null)
  const isDark = theme === 'dark'

  useEffect(() => {
    if (!scrollRef.current) return
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages, isSending, isOpen])

  function openResultsModal(message) {
    setResultsModal({
      open: true,
      title: message?.question ? `Результаты: ${message.question}` : 'Найденные строки',
      rows: message?.rows || [],
    })
  }

  function closeResultsModal() {
    setResultsModal((prev) => ({ ...prev, open: false }))
  }

  async function submitQuestion(rawQuestion) {
    const question = rawQuestion.trim()
    if (!question || isSending) return

    setMessages((prev) => [
      ...prev,
      {
        id: makeId('user'),
        role: 'user',
        text: question,
      },
    ])
    setInput('')
    setIsSending(true)

    const botMsgId = makeId('assistant')
    setMessages((prev) => [
      ...prev,
      {
        id: botMsgId,
        role: 'assistant',
        question,
        text: '',
        rows: [],
        sql: '',
        error: '',
      },
    ])

    try {
      await queryChatStream(question, (event) => {
        setMessages((prev) => 
          prev.map(msg => {
            if (msg.id !== botMsgId) return msg;
            let updatedMsg = { ...msg };
            
            if (event.event === 'status') {
              if (!updatedMsg.text || updatedMsg.text === 'Initializing...' || 
                  updatedMsg.text === 'Checking intent...' ||
                  updatedMsg.text === 'Generating chat response...' ||
                  updatedMsg.text === 'Extracting entities...' ||
                  updatedMsg.text === 'Embedding question...' ||
                  updatedMsg.text === 'Retrieving context...' ||
                  updatedMsg.text === 'Generating SQL...' ||
                  updatedMsg.text === 'Executing query...' ||
                  updatedMsg.text === 'Repairing SQL...' ||
                  updatedMsg.text === 'Summarizing data...') {
                updatedMsg.text = event.data;
              }
            } else if (event.event === 'sql') {
              updatedMsg.sql = event.data;
            } else if (event.event === 'rows') {
              updatedMsg.rows = event.data;
            } else if (event.event === 'row') {
              updatedMsg.rows = [...updatedMsg.rows, event.data];
            } else if (event.event === 'summary_chunk') {
              if (updatedMsg.text === 'Initializing...' || 
                  updatedMsg.text === 'Checking intent...' ||
                  updatedMsg.text === 'Generating chat response...' ||
                  updatedMsg.text === 'Extracting entities...' ||
                  updatedMsg.text === 'Embedding question...' ||
                  updatedMsg.text === 'Retrieving context...' ||
                  updatedMsg.text === 'Generating SQL...' ||
                  updatedMsg.text === 'Executing query...' ||
                  updatedMsg.text === 'Repairing SQL...' ||
                  updatedMsg.text === 'Summarizing data...') {
                updatedMsg.text = event.data;
              } else {
                updatedMsg.text += event.data;
              }
            } else if (event.event === 'error') {
              updatedMsg.error = event.data;
              updatedMsg.text = event.error || event.data;
            } else if (event.event === 'done') {
              // when done, maybe handle final cleanup
            }
            
            return updatedMsg;
          })
        );
      });
    } catch (error) {
      setMessages((prev) => prev.map(msg => {
        if (msg.id !== botMsgId) return msg;
        return {
          ...msg,
          text: error.message || 'Ошибка соединения с чат-сервисом.',
          error: error.message || 'Ошибка соединения с чат-сервисом.',
        };
      }));
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

  return (
    <>
      <div className="fixed bottom-5 right-5 z-[70] sm:bottom-6 sm:right-6">
        <button
          type="button"
          onClick={() => setIsOpen((prev) => !prev)}
          className={`group relative flex h-16 w-16 items-center justify-center rounded-full border text-white shadow-[0_24px_60px_-24px_rgba(14,165,233,0.85)] transition-all duration-300 hover:scale-[1.04] active:scale-[0.98] ${
            isDark
              ? 'border-cyan-300/20 bg-gradient-to-br from-cyan-500 via-sky-500 to-blue-700'
              : 'border-white/80 bg-gradient-to-br from-sky-500 via-cyan-500 to-blue-600'
          }`}
          aria-label={isOpen ? 'Закрыть чат' : 'Открыть чат'}
        >
          <span className="absolute inset-0 rounded-full bg-cyan-300/20 opacity-80 blur-xl transition-opacity duration-300 group-hover:opacity-100" />
          <svg className="relative h-7 w-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-4l-4 4v-4z" />
          </svg>
        </button>
      </div>

      <div
        className={`fixed bottom-24 left-4 right-4 z-[69] transition-all duration-300 sm:bottom-28 sm:left-auto sm:right-6 sm:w-[400px] ${
          isOpen ? 'pointer-events-auto translate-y-0 opacity-100' : 'pointer-events-none translate-y-6 opacity-0'
        }`}
      >
        <section
          className={`overflow-hidden rounded-[28px] border backdrop-blur-xl shadow-[0_40px_100px_-35px_rgba(15,23,42,0.8)] ${
            isDark ? 'border-slate-700/80 bg-slate-950/92' : 'border-sky-100 bg-white/96'
          }`}
        >
          <header
            className={`border-b px-5 py-4 ${
              isDark
                ? 'border-slate-800 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.16),_transparent_42%),linear-gradient(135deg,rgba(15,23,42,0.96),rgba(2,6,23,0.92))]'
                : 'border-sky-100 bg-[radial-gradient(circle_at_top_left,_rgba(14,165,233,0.12),_transparent_42%),linear-gradient(135deg,rgba(248,250,252,0.98),rgba(255,255,255,0.98))]'
            }`}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-3">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-2xl ${isDark ? 'bg-cyan-500/15 text-cyan-300' : 'bg-sky-100 text-sky-700'}`}>
                    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M8 10h.01M12 10h.01M16 10h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4-.8L3 20l1.13-3.39A7.57 7.57 0 013 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                    </svg>
                  </div>

                  <div>
                    <h2 className={`text-sm font-semibold ${isDark ? 'text-white' : 'text-slate-900'}`}>AFM Chat</h2>
                    <p className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                      Запросы к транзакциям на естественном языке
                    </p>
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className={`shrink-0 rounded-full p-2 transition-colors ${
                  isDark ? 'text-slate-400 hover:bg-slate-800 hover:text-white' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'
                }`}
                aria-label="Закрыть чат"
              >
                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </header>

          <div
            ref={scrollRef}
            className={`chat-scrollbar h-[460px] max-h-[70vh] space-y-4 overflow-y-auto px-4 py-4 ${
              isDark ? 'bg-slate-950/85' : 'bg-slate-50/70'
            }`}
          >
            {messages.map((message) => (
              <div key={message.id} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                {message.role === 'user' ? (
                  <div
                    className={`max-w-[85%] rounded-[24px] px-4 py-3 text-sm leading-6 shadow-lg ${
                      isDark
                        ? 'bg-gradient-to-br from-cyan-500 to-sky-600 text-white'
                        : 'bg-gradient-to-br from-sky-500 to-blue-600 text-white'
                    }`}
                  >
                    {message.text}
                  </div>
                ) : (
                  <AssistantMessage message={message} theme={theme} onOpenResults={openResultsModal} />
                )}
              </div>
            ))}

            {isSending && (
              <div className="flex justify-start">
                <div
                  className={`rounded-[24px] border px-4 py-3 text-sm shadow-lg ${
                    isDark ? 'border-cyan-400/10 bg-slate-900/95 text-slate-300' : 'border-sky-100 bg-white text-slate-600'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`h-2 w-2 animate-pulse rounded-full ${isDark ? 'bg-cyan-300' : 'bg-sky-500'}`} />
                    Думаю над ответом...
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className={`border-t px-4 pb-4 pt-3 ${isDark ? 'border-slate-800 bg-slate-950/95' : 'border-sky-100 bg-white/95'}`}>
            <div className="mb-3 flex flex-wrap gap-2">
              {SUGGESTIONS.map((suggestion) => (
                <button
                  key={suggestion}
                  type="button"
                  onClick={() => submitQuestion(suggestion)}
                  disabled={isSending}
                  className={`rounded-full border px-3 py-1.5 text-xs transition-colors ${
                    isDark
                      ? 'border-slate-700 bg-slate-900 text-slate-300 hover:border-cyan-400/40 hover:text-white disabled:opacity-50'
                      : 'border-sky-100 bg-sky-50 text-sky-700 hover:bg-sky-100 disabled:opacity-50'
                  }`}
                >
                  {suggestion}
                </button>
              ))}
            </div>

            <form onSubmit={handleSubmit} className="flex items-end gap-3">
              <div className="flex-1">
                <textarea
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  onKeyDown={handleKeyDown}
                  rows={2}
                  placeholder="Спроси, например: покажи крупные расходы за февраль 2024"
                  className={`w-full resize-none rounded-2xl border px-4 py-3 text-sm outline-none transition-colors ${
                    isDark
                      ? 'border-slate-700 bg-slate-900 text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/50'
                      : 'border-sky-100 bg-slate-50 text-slate-900 placeholder:text-slate-400 focus:border-sky-400'
                  }`}
                />
              </div>

              <button
                type="submit"
                disabled={isSending || !input.trim()}
                className={`h-12 shrink-0 rounded-2xl px-4 text-sm font-medium transition-all ${
                  isSending || !input.trim()
                    ? isDark
                      ? 'cursor-not-allowed bg-slate-800 text-slate-500'
                      : 'cursor-not-allowed bg-slate-200 text-slate-400'
                    : 'bg-gradient-to-r from-cyan-500 to-sky-600 text-white shadow-[0_18px_45px_-22px_rgba(14,165,233,0.9)] hover:translate-y-[-1px]'
                }`}
              >
                Отправить
              </button>
            </form>
          </div>
        </section>
      </div>

      <ResultsModal modal={resultsModal} theme={theme} onClose={closeResultsModal} />
    </>
  )
}

export default ChatWidget
