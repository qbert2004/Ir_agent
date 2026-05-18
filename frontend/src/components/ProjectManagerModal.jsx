import React, { useEffect, useMemo, useState } from 'react'
import { FolderOpen, Plus, Trash2, X, ShieldCheck, ChevronUp, ChevronDown, Loader2, Archive } from 'lucide-react'

function ProjectManagerModal({
  open = false,
  theme = 'dark',
  projects = [],
  activeProjectId = '',
  onClose,
  onSelectProject,
  onCreateProject,
  onDeleteProject,
}) {
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmProject, setConfirmProject] = useState(null)

  const isDark = theme === 'dark'
  const activeProject = useMemo(
    () => projects.find((project) => project.project_id === activeProjectId) || null,
    [projects, activeProjectId]
  )

  useEffect(() => {
    if (!open) {
      setName('')
      setError('')
      setBusy(false)
      setConfirmProject(null)
      return undefined
    }

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        onClose?.()
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  if (!open) return null

  const handleCreate = async () => {
    const normalized = name.trim()
    if (!normalized) {
      setError('Введите название проекта')
      return
    }

    try {
      setBusy(true)
      setError('')
      await onCreateProject?.(normalized)
      setName('')
      onClose?.()
    } catch (err) {
      setError(err?.message || 'Не удалось создать проект')
    } finally {
      setBusy(false)
    }
  }

  const handleSelect = async (projectId) => {
    if (!projectId || projectId === activeProjectId) {
      onClose?.()
      return
    }

    try {
      setBusy(true)
      setError('')
      await onSelectProject?.(projectId)
      onClose?.()
    } catch (err) {
      setError(err?.message || 'Не удалось переключить проект')
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async () => {
    if (!confirmProject?.project_id) return

    try {
      setBusy(true)
      setError('')
      await onDeleteProject?.(confirmProject.project_id)
      setConfirmProject(null)
      onClose?.()
    } catch (err) {
      setError(err?.message || 'Не удалось удалить проект')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 sm:p-6 lg:p-8">
      {/* Backdrop */}
      <button
        type="button"
        aria-label="Закрыть управление проектами"
        className="absolute inset-0 bg-slate-950/60 backdrop-blur-md transition-opacity duration-300"
        onClick={() => onClose?.()}
      />

      <div
        className={`relative z-10 flex h-full max-h-[85vh] w-full max-w-6xl overflow-hidden rounded-[32px] border shadow-2xl transition-all duration-500 animate-in zoom-in-95 ${
          isDark 
            ? 'border-white/10 bg-[#101014]/95 text-white' 
            : 'border-slate-200 bg-white/95 text-slate-900'
        }`}
      >
        {/* Sidebar (Project Selector) */}
        <div className={`flex w-[280px] flex-col border-r ${isDark ? 'border-white/5 bg-white/[0.02]' : 'border-slate-100 bg-slate-50/50'}`}>
          <div className={`p-5 border-b ${isDark ? 'border-white/5' : 'border-slate-100'}`}>
            <div className="flex items-center gap-3">
              <div className={`flex h-8 w-8 items-center justify-center rounded-xl ${isDark ? 'bg-indigo-500/10 text-indigo-400' : 'bg-indigo-50 text-indigo-600'}`}>
                <Archive size={16} />
              </div>
              <div>
                <p className={`text-[8px] font-black uppercase tracking-[0.25em] ${isDark ? 'text-zinc-500' : 'text-slate-400'}`}>
                  Континент
                </p>
                <h3 className="text-sm font-black tracking-tight">Рабочие пространства</h3>
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2 custom-scrollbar">
            {projects.map((project) => {
              const active = project.project_id === activeProjectId
              return (
                <button
                  key={project.project_id}
                  onClick={() => handleSelect(project.project_id)}
                  disabled={busy}
                  className={`group relative flex w-full flex-col gap-1 rounded-xl border p-3 text-left transition-all duration-300 ${
                    active
                      ? isDark
                        ? 'border-indigo-500/40 bg-indigo-500/10 shadow-[0_0_20px_rgba(99,102,241,0.1)]'
                        : 'border-indigo-300 bg-indigo-50 shadow-sm'
                      : 'border-transparent hover:bg-white/5 dark:hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {active && <div className="h-1 w-1 rounded-full bg-indigo-500 shrink-0" />}
                    <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded-full border ${
                      active 
                        ? 'border-indigo-500/30 text-indigo-500 bg-indigo-500/5' 
                        : 'border-transparent text-zinc-500'
                    }`}>
                      {active ? 'Активен' : 'Проект'}
                    </span>
                  </div>
                  <div className={`text-xs font-black transition-colors ${active ? 'text-indigo-600 dark:text-indigo-400' : 'text-zinc-400'}`}>
                    {project.name}
                  </div>
                  
                  {/* Delete hovering trigger */}
                  {!active && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setConfirmProject(project)
                      }}
                      className="absolute right-3 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 p-1.5 rounded-lg hover:bg-rose-500/10 text-rose-400 transition-all duration-200"
                    >
                      <Trash2 size={12} />
                    </button>
                  )}
                </button>
              )
            })}
          </div>

          <div className={`p-3 border-t ${isDark ? 'border-white/5' : 'border-slate-100'}`}>
             <p className="text-[9px] text-zinc-500 text-center font-medium italic">Синхронизация активна</p>
          </div>
        </div>

        {/* Main Content (Creation & Management Dossier) */}
        <div className="flex flex-1 flex-col overflow-hidden">
          <div className="flex-1 overflow-y-auto p-6 sm:p-10 space-y-10 custom-scrollbar">
            
            <section className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="mb-5">
                <p className={`text-[9px] font-black uppercase tracking-[0.3em] ${isDark ? 'text-zinc-600' : 'text-slate-400'}`}>
                  Настройка проекта
                </p>
                <h2 className="mt-1 text-2xl font-black tracking-tight">
                  Новое пространство
                </h2>
                <p className={`mt-3 text-sm leading-relaxed max-w-2xl ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>
                  Создайте изолированный проект для управления транзакциями и аналитикой.
                </p>
              </div>

              <div className={`rounded-3xl border p-6 space-y-4 ${isDark ? 'border-white/5 bg-white/[0.02]' : 'border-slate-100 bg-slate-50'}`}>
                <div className="space-y-3">
                  <label className="block">
                    <span className={`mb-2 block text-[9px] font-black uppercase tracking-[0.25em] ${isDark ? 'text-zinc-500' : 'text-slate-400'}`}>
                      Название проекта
                    </span>
                    <input
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                      placeholder="Например: Операция 'Альянс'..."
                      className={`w-full rounded-xl border px-5 py-3 text-sm font-bold outline-none transition-all ${
                        isDark
                          ? 'border-white/10 bg-black text-white placeholder:text-zinc-700 focus:border-indigo-500/50'
                          : 'border-slate-200 bg-white text-slate-900 placeholder:text-slate-300 focus:border-indigo-400'
                      }`}
                    />
                  </label>

                  {error && (
                    <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-bold">
                      {error}
                    </div>
                  )}

                  <div className="flex items-center gap-3 pt-2">
                    <button
                      onClick={handleCreate}
                      disabled={busy}
                      className="flex items-center gap-2 rounded-xl bg-indigo-600 px-6 py-3 text-[10px] font-black uppercase tracking-widest text-white transition-all hover:bg-indigo-500 hover:scale-[1.02] active:scale-95 disabled:opacity-50"
                    >
                      {busy ? <Loader2 className="animate-spin h-4 w-4" /> : <Plus className="h-4 w-4" />}
                      {busy ? 'Создание...' : 'Создать проект'}
                    </button>
                    <button
                      onClick={() => onClose?.()}
                      className={`px-6 py-3 text-[10px] font-black uppercase tracking-widest rounded-xl border transition-all ${
                        isDark ? 'border-white/10 text-zinc-400 hover:bg-white/5' : 'border-slate-200 text-slate-500 hover:bg-slate-50'
                      }`}
                    >
                      Отмена
                    </button>
                  </div>
                </div>
              </div>
            </section>

            {/* Footprint Summary */}
            <section className="grid sm:grid-cols-2 gap-4 animate-in fade-in slide-in-from-bottom-8 duration-700">
              <div className={`p-5 rounded-2xl border ${isDark ? 'border-white/5 bg-white/[0.01]' : 'border-slate-100 bg-white shadow-sm'}`}>
                <div className="flex items-center gap-2 mb-3">
                  <div className="p-1.5 rounded-lg bg-indigo-500/10 text-indigo-500">
                    <FolderOpen size={16} />
                  </div>
                  <span className={`text-[9px] font-black uppercase tracking-widest ${isDark ? 'text-zinc-500' : 'text-slate-400'}`}>
                    Текущий статус
                  </span>
                </div>
                <h4 className="text-lg font-black mb-0.5">{activeProject?.name || 'Нет выбора'}</h4>
                <p className="text-[10px] text-zinc-500 font-medium">Активное рабочее пространство</p>
              </div>

              <div className={`p-5 rounded-2xl border ${isDark ? 'border-white/5 bg-white/[0.01]' : 'border-slate-100 bg-white shadow-sm'}`}>
                <div className="flex items-center gap-2 mb-3">
                  <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-500">
                    <ShieldCheck size={16} />
                  </div>
                  <span className={`text-[9px] font-black uppercase tracking-widest ${isDark ? 'text-zinc-500' : 'text-slate-400'}`}>
                    Безопасность
                  </span>
                </div>
                <h4 className="text-lg font-black mb-0.5">{projects.length} Проектов</h4>
                <p className="text-[10px] text-zinc-500 font-medium">Изолированные контейнеры</p>
              </div>
            </section>
          </div>
          
          <div className={`p-4 border-t flex justify-end gap-2 ${isDark ? 'border-white/5 bg-black/40' : 'border-slate-100 bg-slate-50/50'}`}>
             <button
                onClick={() => onClose?.()}
                className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-[9px] font-black uppercase tracking-widest transition-all ${
                  isDark ? 'text-zinc-500 hover:text-white' : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                Закрыть
                <X size={12} />
              </button>
          </div>
        </div>
      </div>

      {/* Delete Confirmation (Upgraded UI) */}
      {confirmProject && (
        <div className="fixed inset-0 z-[150] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-300" onClick={() => setConfirmProject(null)} />
          <div className={`relative z-10 w-full max-w-md rounded-[32px] border p-8 shadow-2xl animate-in zoom-in-95 duration-300 ${
            isDark ? 'border-white/10 bg-[#101014]' : 'border-slate-200 bg-white'
          }`}>
             <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-500 text-[9px] font-black uppercase tracking-widest border border-rose-500/30">
                Критическая угроза
              </span>
            <h3 className="mt-4 text-2xl font-black tracking-tight">Удалить проект?</h3>
            <p className={`mt-4 text-sm leading-relaxed ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>
              Проект <span className="font-black text-rose-500">{confirmProject.name}</span> будет стерт навсегда из системы вместе со всеми транзакциями и аналитикой.
            </p>
            <div className="mt-8 flex gap-3">
               <button
                onClick={handleDelete}
                disabled={busy}
                className="flex-1 rounded-2xl bg-rose-600 py-4 text-xs font-black uppercase tracking-widest text-white hover:bg-rose-500 transition-all shadow-[0_20px_40px_-12px_rgba(244,63,94,0.3)]"
              >
                {busy ? 'Удаляем...' : 'Стереть навсегда'}
              </button>
              <button
                onClick={() => setConfirmProject(null)}
                className={`flex-1 rounded-2xl border py-4 text-xs font-black uppercase tracking-widest transition-all ${
                  isDark ? 'border-white/10 hover:bg-white/5 text-zinc-400' : 'border-slate-200 hover:bg-slate-50 text-slate-500'
                }`}
              >
                Отмена
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ProjectManagerModal

