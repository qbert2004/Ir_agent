import React from 'react'
import logo from '../assets/logo.jpeg'
import { 
  Database, 
  BarChart3, 
  MessageSquare, 
  Share2,
  FileText,
  AlertTriangle,
  FolderOpen,
  UploadCloud,
  History, 
} from 'lucide-react'

function AdminIcon({ className = 'w-7 h-7' }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M9 11.25a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" />
      <path d="M3.75 19.25a5.25 5.25 0 0 1 10.2-1.85" />
      <path d="M18.25 12.75h.25a.8.8 0 0 1 .77.61l.2.82a3.6 3.6 0 0 1 .48.28l.8-.24a.8.8 0 0 1 .9.33l.14.23a.8.8 0 0 1-.11.95l-.56.6a3.7 3.7 0 0 1 0 .56l.56.6a.8.8 0 0 1 .11.95l-.14.23a.8.8 0 0 1-.9.33l-.8-.24a3.6 3.6 0 0 1-.48.28l-.2.82a.8.8 0 0 1-.77.61h-.25a.8.8 0 0 1-.77-.61l-.2-.82a3.6 3.6 0 0 1-.48-.28l-.8.24a.8.8 0 0 1-.9-.33l-.14-.23a.8.8 0 0 1 .11-.95l.56-.6a3.7 3.7 0 0 1 0-.56l-.56-.6a.8.8 0 0 1-.11-.95l.14-.23a.8.8 0 0 1 .9-.33l.8.24c.15-.1.31-.2.48-.28l.2-.82a.8.8 0 0 1 .77-.61Z" />
      <path d="M18.38 18.12a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z" />
    </svg>
  )
}

function Sidebar({
  activeTab,
  onTabChange,
  tabs,
  onUpload,
  uploadLoading = false,
  riskWarningCount = 0,
  onOpenRiskReview,
  isAdmin = false,
  onOpenProjects,
  onOpenHistory,
}) {
  // Mapping of tab IDs to icons
  const iconMap = {
    transactions: Database,
    analytics: BarChart3,
    comparison: FileText,
    network: Share2,
    chat: MessageSquare
  }

  return (
    <aside className="w-16 flex flex-col items-center py-4 border-r border-slate-200 dark:border-[#1F1F1F] bg-white dark:bg-[#09090B] z-50 transition-colors shrink-0">
      {/* Brand Logo (Replaced Zap with logo.jpeg) */}
      <div className="w-10 h-10 rounded-xl overflow-hidden shadow-lg shadow-indigo-500/10 mb-8 cursor-pointer active:scale-95 transition-all border border-slate-100 dark:border-[#1F1F1F]">
        <img src={logo} alt="FinAnalytica" className="w-full h-full object-cover" />
      </div>

      {/* Primary Nav - Dynamic Tabs */}
      <nav className="flex flex-col gap-5">
        {tabs.map((tab) => {
          const Icon = iconMap[tab.id] || Database
          const isActive = activeTab === tab.id
          
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              title={tab.label}
              className={`p-2.5 rounded-xl transition-all duration-200 group relative ${
                isActive
                  ? 'bg-indigo-50 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-400'
                  : 'text-slate-400 hover:bg-slate-50 dark:hover:bg-zinc-900'
              }`}
            >
              <Icon className="w-5 h-5 block" />
              
              {/* Tooltip or Label on Hover (Visual only) */}
              <span className="absolute left-full ml-3 px-2 py-1 bg-slate-900 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-[100] font-bold uppercase tracking-widest">
                {tab.label}
              </span>
            </button>
          )
        })}

        <button
          type="button"
          onClick={onUpload}
          title={uploadLoading ? 'Uploading...' : 'Upload'}
          disabled={uploadLoading}
          className={`p-2.5 rounded-xl transition-all duration-200 group relative ${
            uploadLoading
              ? 'cursor-wait text-indigo-500 bg-indigo-50 dark:bg-indigo-900/30 dark:text-indigo-400'
              : 'text-slate-400 hover:bg-slate-50 dark:hover:bg-zinc-900 hover:text-indigo-600 dark:hover:text-indigo-400'
          }`}
        >
          <UploadCloud className={`w-5 h-5 block ${uploadLoading ? 'animate-pulse' : ''}`} />

          <span className="absolute left-full ml-3 px-2 py-1 bg-slate-900 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-[100] font-bold uppercase tracking-widest">
            {uploadLoading ? 'Uploading...' : 'Upload'}
          </span>
        </button>

        {riskWarningCount > 0 && (
          <button
            type="button"
            onClick={onOpenRiskReview}
            title="Risk Review"
            className="p-2.5 rounded-xl transition-all duration-200 group relative text-rose-500 bg-rose-50 dark:bg-rose-900/20 dark:text-rose-300 hover:bg-rose-100 dark:hover:bg-rose-900/30"
          >
            <AlertTriangle className="w-5 h-5 block" />
            <span className="absolute -right-1 -top-1 min-w-[18px] rounded-full bg-rose-500 px-1.5 py-0.5 text-[10px] font-black leading-none text-white">
              {riskWarningCount}
            </span>

            <span className="absolute left-full ml-3 px-2 py-1 bg-slate-900 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-[100] font-bold uppercase tracking-widest">
              Risk Review
            </span>
          </button>
        )}
      </nav>

      {/* Bottom Nav */}
      <div className="mt-auto flex flex-col items-center gap-3">
        <button
          type="button"
          onClick={onOpenProjects}
          title="Projects"
          className="p-2.5 rounded-xl text-slate-400 hover:bg-slate-50 dark:hover:bg-zinc-900 hover:text-indigo-600 dark:hover:text-indigo-400 transition-all duration-200 group relative"
        >
          <FolderOpen className="w-5 h-5 block" />
          <span className="absolute left-full ml-3 px-2 py-1 bg-slate-900 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-[100] font-bold uppercase tracking-widest">
            Projects
          </span>
        </button>

        {isAdmin && (
          <button
            type="button"
            onClick={() => window.open('http://127.0.0.1:8003/admin', '_blank', 'noopener,noreferrer')}
            title="Admin"
            className="p-2.5 rounded-xl text-slate-400 hover:bg-slate-50 dark:hover:bg-zinc-900 hover:text-indigo-600 dark:hover:text-indigo-400 transition-all duration-200 group relative"
          >
            <AdminIcon className="w-7 h-7 block" />
            <span className="absolute left-full ml-3 px-2 py-1 bg-slate-900 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-[100] font-bold uppercase tracking-widest">
              Admin
            </span>
          </button>
        )}

        <button
          type="button"
          onClick={onOpenHistory}
          title="History & Archive"
          className="p-2.5 rounded-xl text-slate-400 hover:bg-slate-50 dark:hover:bg-zinc-900 hover:text-indigo-600 dark:hover:text-indigo-400 transition-all duration-200 group relative"
        >
          <History className="w-5 h-5 block" />
          <span className="absolute left-full ml-3 px-2 py-1 bg-slate-900 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap z-[100] font-bold uppercase tracking-widest">
            History & Archive
          </span>
        </button>
      </div>
    </aside>
  )
}

export default Sidebar
