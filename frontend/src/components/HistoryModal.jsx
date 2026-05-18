import React, { useState, useEffect } from 'react'
import { 
  X, Upload, MessageSquare, AlertTriangle, FileText, 
  Clock, Archive, ArchiveRestore, ChevronDown, ChevronUp,
  Activity, Users, List, ShieldCheck
} from 'lucide-react'
import { fetchProjectFiles, fetchChatHistory } from '../services/api'

function HistoryModal({ 
  isOpen, 
  onClose, 
  projectId, 
  archivedFraud = [], 
  onUnarchiveFraud 
}) {
  const [activeTab, setActiveTab] = useState('uploads')
  const [uploads, setUploads] = useState([])
  const [chatHistory, setChatHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [expandedFraudCode, setExpandedFraudCode] = useState(null)
  const [showTransactions, setShowTransactions] = useState(false)

  useEffect(() => {
    if (isOpen) {
      loadData()
    }
    // Reset transaction toggle when modal opens
    setShowTransactions(false)
  }, [isOpen, activeTab, projectId])

  const handleToggleFraud = (code) => {
    if (expandedFraudCode === code) {
      setExpandedFraudCode(null)
    } else {
      setExpandedFraudCode(code)
      setShowTransactions(false) // Reset table state for new expanded item
    }
  }

  const loadData = async () => {
    setLoading(true)
    try {
      if (activeTab === 'uploads') {
        const res = await fetchProjectFiles(projectId)
        setUploads(res.items || [])
      } else if (activeTab === 'chat') {
        const res = await fetchChatHistory()
        setChatHistory(res.items || [])
      }
    } catch (err) {
      console.error('Failed to fetch history:', err)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityLabel = (severity) => {
    if (severity === 'high') return 'Высокий риск'
    if (severity === 'medium') return 'Средний риск'
    return 'Нужна проверка'
  }

  const getSeverityClasses = (severity) => {
    if (severity === 'high') {
      return 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200'
    }
    if (severity === 'medium') {
      return 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200'
    }
    return 'border-cyan-200 bg-cyan-50 text-cyan-700 dark:border-cyan-500/30 dark:bg-cyan-500/10 dark:text-cyan-200'
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/60 p-4 backdrop-blur-md animate-in fade-in duration-300">
      <div className="w-full max-w-5xl overflow-hidden rounded-[28px] border border-white/10 bg-white shadow-2xl dark:bg-[#0C0C0E]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4 dark:border-white/5">
          <div>
            <h2 className="text-lg font-black text-slate-800 dark:text-white">History & Archive</h2>
            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-400 dark:text-zinc-500 mt-0.5">
              Project Logs & Stored Detections
            </p>
          </div>
          <button
            onClick={onClose}
            className="rounded-full p-2 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-white/5 dark:hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Tabs Nav */}
        <div className="flex border-b border-slate-100 bg-slate-50/30 px-6 dark:border-white/5 dark:bg-white/5">
          {[
            { id: 'uploads', label: 'Uploads', icon: Upload },
            { id: 'chat', label: 'Chat Log', icon: MessageSquare },
            { id: 'fraud', label: 'Fraud', icon: AlertTriangle },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 border-b-2 px-4 py-3 text-[10px] font-black uppercase tracking-widest transition-all ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-slate-400 hover:text-slate-600 dark:hover:text-zinc-300'
              }`}
            >
              <tab.icon className="h-3 w-3" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="max-h-[60vh] overflow-y-auto p-5 custom-scrollbar">
          {loading ? (
            <div className="flex h-32 items-center justify-center">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
            </div>
          ) : (
            <div className="space-y-3">
              {activeTab === 'uploads' && (
                <>
                  {uploads.length === 0 ? (
                    <EmptyState message="No files uploaded" />
                  ) : (
                    uploads.map((file) => (
                      <HistoryItem 
                        key={file.file_id}
                        icon={FileText}
                        title={file.original_filename}
                        subtitle={`${file.source_bank} • ${new Date(file.uploaded_at).toLocaleString()}`}
                      />
                    ))
                  )}
                </>
              )}

              {activeTab === 'chat' && (
                <>
                  {chatHistory.length === 0 ? (
                    <EmptyState message="Chat history is empty" />
                  ) : (
                    chatHistory.map((chat) => (
                      <HistoryItem 
                        key={chat.id}
                        icon={MessageSquare}
                        title={chat.question}
                        subtitle={new Date(chat.created_at).toLocaleString()}
                        status={chat.execution_success ? 'Success' : 'Failed'}
                      />
                    ))
                  )}
                </>
              )}

              {activeTab === 'fraud' && (
                <>
                  {archivedFraud.length === 0 ? (
                    <EmptyState message="No archived reports" />
                  ) : (
                    archivedFraud.map((fraud, idx) => {
                      const expanded = expandedFraudCode === (fraud.uid || fraud.code)
                      const isAccepted = fraud.resolution === 'accepted'

                      return (
                        <div 
                          key={`${fraud.uid || fraud.code}-${idx}`}
                          className="flex flex-col gap-1.5 rounded-[22px] border border-slate-100 bg-white p-1.5 dark:border-white/5 dark:bg-white/[0.02]"
                        >
                          <div 
                            onClick={() => handleToggleFraud(fraud.uid || fraud.code)}
                            className={`flex cursor-pointer items-start justify-between gap-3 rounded-[18px] border p-4 transition-all ${
                              isAccepted 
                                ? 'border-emerald-100 bg-emerald-50/20 hover:bg-emerald-50/50 dark:border-emerald-500/10 dark:bg-emerald-500/5 dark:hover:bg-emerald-500/10'
                                : 'border-rose-100 bg-rose-50/20 hover:bg-rose-50/50 dark:border-rose-500/10 dark:bg-rose-500/5 dark:hover:bg-rose-500/10'
                            }`}
                          >
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                {isAccepted ? (
                                  <ShieldCheck className="h-4 w-4 text-emerald-500" />
                                ) : (
                                  <AlertTriangle className="h-4 w-4 text-rose-500" />
                                )}
                                <h4 className="text-sm font-black text-slate-800 dark:text-white">{fraud.title}</h4>
                                <span className={`rounded-full border px-2 py-0.5 text-[8px] font-black uppercase tracking-widest ${
                                  isAccepted 
                                    ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200'
                                    : getSeverityClasses(fraud.severity)
                                }`}>
                                  {isAccepted ? 'Проверено' : getSeverityLabel(fraud.severity)}
                                </span>
                              </div>
                              <p className="mt-1.5 text-xs leading-relaxed text-slate-500 dark:text-zinc-400">
                                {fraud.summary}
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  onUnarchiveFraud(fraud.uid || fraud.code)
                                }}
                                className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-400 transition-all hover:bg-slate-50 hover:text-indigo-500 dark:border-white/10 dark:bg-zinc-900 dark:hover:bg-white/10"
                                title="Вернуть из архива"
                              >
                                <ArchiveRestore className="h-3.5 w-3.5" />
                              </button>
                              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-100 text-slate-400 dark:bg-white/5">
                                {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                              </div>
                            </div>
                          </div>

                          {expanded && (
                            <div className="animate-in slide-in-from-top-2 duration-200 space-y-5 px-3 py-4">
                              {/* Indicators Section */}
                              {fraud.indicators?.length > 0 && (
                                <div className="space-y-1.5">
                                  <h5 className="flex items-center gap-2 text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-500">
                                    <Activity className="h-2.5 w-2.5" /> Indicators
                                  </h5>
                                  <div className="flex flex-wrap gap-2">
                                    {fraud.indicators.map((ind, i) => (
                                      <div key={i} className="flex-1 min-w-[120px] rounded-xl border border-slate-100 bg-slate-50/50 p-2.5 dark:border-white/5 dark:bg-white/5">
                                        <div className="text-[8px] font-bold text-slate-400 dark:text-zinc-500 uppercase tracking-widest mb-0.5">{ind.label}</div>
                                        <div className="text-[11px] font-black text-slate-800 dark:text-white">{ind.value}</div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Counterparties Section */}
                              {fraud.counterparties?.length > 0 && (
                                <div className="space-y-2">
                                  <h5 className="flex items-center gap-2 text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-500">
                                    <Users className="h-2.5 w-2.5" /> Connected Accounts
                                  </h5>
                                  <div className="grid grid-cols-1 gap-2">
                                    {fraud.counterparties.map((cp, i) => (
                                      <div key={i} className="rounded-xl border border-slate-100 bg-slate-50/50 p-3 dark:border-white/5 dark:bg-white/5">
                                        <div className="flex justify-between items-start mb-1.5">
                                          <div>
                                            <div className="text-[9px] font-bold text-indigo-500 uppercase tracking-widest mb-0.5">{cp.role}</div>
                                            <div className="text-xs font-black text-slate-800 dark:text-white">{cp.name}</div>
                                            <div className="text-[9px] font-medium text-slate-400 mt-0.5">{cp.identifier}</div>
                                          </div>
                                          <div className="text-right">
                                            <div className="text-xs font-black text-slate-800 dark:text-white">{cp.turnover}</div>
                                            <div className="text-[8px] font-medium text-slate-400">{cp.transaction_count} tx</div>
                                          </div>
                                        </div>
                                        <div className="flex flex-wrap gap-1 mt-2">
                                          {cp.articles?.map(a => (
                                            <span key={a} className="rounded-full bg-rose-500/10 border border-rose-500/20 px-1.5 py-0.5 text-[8px] font-black text-rose-500 uppercase tracking-widests">
                                              {a}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Transactions Section */}
                              {fraud.sample_transactions?.length > 0 && (
                                <div className="space-y-2">
                                  <button
                                    onClick={() => setShowTransactions(!showTransactions)}
                                    className="flex w-full items-center justify-between group"
                                  >
                                    <h5 className="flex items-center gap-2 text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-500 group-hover:text-indigo-500 transition-colors">
                                      <List className="h-2.5 w-2.5" /> Core Transactions
                                    </h5>
                                    <span className="text-[8px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-600 group-hover:text-indigo-400 transition-colors">
                                      {showTransactions ? 'Hide Details' : 'Show Details'}
                                    </span>
                                  </button>

                                  {showTransactions && (
                                    <div className="overflow-hidden rounded-xl border border-slate-100 dark:border-white/5 animate-in slide-in-from-top-1 duration-200">
                                      <table className="w-full text-left border-collapse">
                                        <thead className="bg-slate-50/50 dark:bg-white/5 text-[8px] font-black uppercase tracking-widest text-slate-400">
                                          <tr>
                                            <th className="px-3 py-2">Date</th>
                                            <th className="px-3 py-2 text-right">Amount</th>
                                            <th className="px-3 py-2">Details</th>
                                          </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-50 dark:divide-white/5 text-[11px]">
                                          {fraud.sample_transactions.map((tx, i) => (
                                            <tr key={i} className="hover:bg-slate-50/80 dark:hover:bg-white/[0.02]">
                                              <td className="px-3 py-2 text-slate-500 whitespace-nowrap">{tx.happened_at}</td>
                                              <td className="px-3 py-2 text-right font-black text-slate-800 dark:text-white">{tx.amount}</td>
                                              <td className="px-3 py-2">
                                                <div className="font-bold text-slate-700 dark:text-zinc-300 truncate max-w-[120px]">{tx.counterparty}</div>
                                                <div className="text-[9px] text-slate-400 truncate max-w-[120px]">{tx.purpose}</div>
                                              </td>
                                            </tr>
                                          ))}
                                        </tbody>
                                      </table>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function HistoryItem({ icon: Icon, title, subtitle, status }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-slate-100 bg-slate-50/50 p-3 transition-all hover:bg-slate-50 dark:border-white/5 dark:bg-white/5 dark:hover:bg-white/[0.07]">
      <div className="rounded-lg bg-white p-2 shadow-sm dark:bg-zinc-900">
        {React.createElement(Icon, { className: 'h-3.5 w-3.5 text-slate-400' })}
      </div>
      <div className="flex-1 overflow-hidden">
        <h4 className="truncate text-xs font-bold text-slate-800 dark:text-white">{title}</h4>
        <p className="text-[10px] font-medium text-slate-400 dark:text-zinc-500">{subtitle}</p>
      </div>
      {status && (
        <span className={`text-[9px] font-black uppercase tracking-widest ${
          status === 'Success' ? 'text-emerald-500' : 'text-rose-500'
        }`}>
          {status}
        </span>
      )}
    </div>
  )
}

function EmptyState({ message }) {
  return (
    <div className="flex h-24 flex-col items-center justify-center text-center">
      <Clock className="mb-1.5 h-5 w-5 text-slate-200 dark:text-zinc-800" />
      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-zinc-600">{message}</p>
    </div>
  )
}

export default HistoryModal
