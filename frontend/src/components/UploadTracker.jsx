import React from 'react'
import { CheckCircle2, CircleDashed, AlertCircle, X, ChevronDown, Minimize2, Maximize2 } from 'lucide-react'

const UploadTracker = ({ tasks, isVisible, onClose, onMinimize, isMinimized, onCancelTask }) => {
  if (!isVisible && !isMinimized) return null

  const completedCount = tasks.filter(t => t.status === 'done' || t.status === 'error' || t.status === 'cancelled').length
  const totalCount = tasks.length
  const activeTasksCount = tasks.filter(t => t.status === 'pending' || t.status === 'processing' || t.status === 'uploading').length
  const progress = totalCount > 0 ? (completedCount / totalCount) * 100 : 0
  
  if (isMinimized) {
    return (
      <div 
        onClick={onMinimize}
        className="fixed bottom-6 right-6 z-[200] flex cursor-pointer items-center gap-3 rounded-2xl border border-slate-200 bg-white p-3 shadow-xl transition-all hover:scale-105 dark:border-white/10 dark:bg-zinc-900"
      >
        <div className="relative">
          <CircleDashed className={`h-6 w-6 animate-spin text-indigo-500 ${activeTasksCount === 0 ? 'hidden' : ''}`} />
          <CheckCircle2 className={`h-6 w-6 text-emerald-500 ${activeTasksCount === 0 ? '' : 'hidden'}`} />
          <div className="absolute inset-0 flex items-center justify-center text-[8px] font-bold">
            {Math.round(progress)}%
          </div>
        </div>
        <div className="flex flex-col">
          <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Загрузка документов</span>
          <span className="text-xs font-bold text-slate-800 dark:text-white">
            {completedCount} из {totalCount} завершено
          </span>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-[160] flex items-end justify-end p-6 pointer-events-none">
      <div className="pointer-events-auto w-full max-w-sm rounded-[32px] border border-slate-200 bg-white shadow-2xl dark:border-white/10 dark:bg-[#101014]/95 backdrop-blur-md overflow-hidden flex flex-col max-h-[500px] animate-in slide-in-from-bottom-5 duration-300">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 p-5 dark:border-white/5 bg-slate-50/50 dark:bg-white/5">
          <div>
            <h3 className="text-sm font-black text-slate-900 dark:text-white uppercase tracking-wider">Очередь загрузки</h3>
            <p className="text-[10px] font-medium text-slate-400 mt-0.5">Всего файлов: {totalCount}</p>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={onMinimize}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-200 dark:hover:bg-white/10 transition-colors"
              title="Свернуть"
            >
              <Minimize2 className="h-4 w-4" />
            </button>
            <button 
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-rose-100 hover:text-rose-600 dark:hover:bg-rose-500/20 dark:hover:text-rose-400 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="h-1 bg-slate-100 dark:bg-white/5 w-full">
          <div 
            className="h-full bg-indigo-500 transition-all duration-500 ease-out" 
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* File List */}
        <div className="flex-1 overflow-y-auto p-2 custom-scrollbar space-y-1">
          {tasks.map((task, idx) => (
            <div 
              key={idx} 
              className={`flex items-center gap-3 rounded-xl p-3 transition-colors ${
                task.status === 'processing' || task.status === 'uploading' 
                  ? 'bg-indigo-50/50 dark:bg-indigo-500/5' 
                  : (task.status === 'cancelled' ? 'opacity-50 grayscale' : 'hover:bg-slate-50 dark:hover:bg-white/5')
              }`}
            >
              <div className="flex-shrink-0">
                {task.status === 'done' && <CheckCircle2 className="h-5 w-5 text-emerald-500" />}
                {task.status === 'error' && <AlertCircle className="h-5 w-5 text-rose-500" />}
                {task.status === 'cancelled' && <X className="h-5 w-5 text-slate-400" />}
                {(task.status === 'processing' || task.status === 'uploading') && (
                  <CircleDashed className="h-5 w-5 animate-spin text-indigo-500" />
                )}
                {task.status === 'pending' && <div className="h-5 w-5 rounded-full border-2 border-slate-200 dark:border-white/10" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-bold text-slate-800 dark:text-zinc-200">
                    {task.name}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="flex-shrink-0 text-[9px] font-black uppercase tracking-widest opacity-50">
                      {task.status === 'done' && 'Готово'}
                      {task.status === 'error' && 'Ошибка'}
                      {task.status === 'processing' && 'Анализ...'}
                      {task.status === 'uploading' && 'Загрузка...'}
                      {task.status === 'pending' && 'В очереди'}
                      {task.status === 'cancelled' && 'Отменен'}
                    </span>
                    {task.status === 'pending' && onCancelTask && (
                      <button 
                        onClick={() => onCancelTask(idx)}
                        className="rounded-full bg-slate-100 p-1 text-slate-400 hover:bg-rose-100 hover:text-rose-600 dark:bg-white/5"
                        title="Отменить"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                </div>
                {task.message && (
                  <div className="mt-1 flex flex-wrap gap-2">
                    {task.status === 'done' && task.stats ? (
                      <span className="text-[9px] font-bold text-emerald-600 dark:text-emerald-400">
                        +{task.stats.inserted} Добавлено
                      </span>
                    ) : (
                      <p className={`truncate text-[9px] ${task.status === 'error' ? 'text-rose-500' : 'text-slate-400'}`}>
                        {task.message}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        {activeTasksCount === 0 && (
          <div className="p-4 bg-emerald-500 text-white text-center animate-in fade-in slide-in-from-bottom-2">
            <span className="text-[10px] font-black uppercase tracking-[0.2em]">Все документы обработаны</span>
          </div>
        )}
      </div>
    </div>
  )
}

export default UploadTracker
