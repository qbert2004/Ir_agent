import React, { useState } from 'react'
import { 
  Settings as SettingsIcon, 
  Cpu, 
  Database, 
  Globe, 
  ShieldAlert, 
  Activity, 
  FileText, 
  Clock, 
  Save, 
  RotateCcw,
  Zap,
  Server,
  Terminal,
  Layers
} from 'lucide-react'

function SettingsSection({ title, icon: Icon, children }) {
  return (
    <div className="bg-white/80 dark:bg-zinc-900/60 backdrop-blur-md rounded-[28px] border border-slate-100 dark:border-[#1F1F1F] p-8 shadow-sm transition-all hover:shadow-md animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-2xl bg-indigo-500/10 text-indigo-500">
          {React.createElement(Icon, { className: 'w-6 h-6' })}
        </div>
        <h3 className="text-xl font-black tracking-tight text-slate-800 dark:text-zinc-100 uppercase italic">
          {title}
        </h3>
      </div>
      <div className="space-y-6">
        {children}
      </div>
    </div>
  )
}

function SettingItem({ label, description, children }) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <div className="flex flex-col">
          <span className="text-sm font-black text-slate-700 dark:text-zinc-200 tracking-wide">
            {label}
          </span>
          <span className="text-xs text-slate-400 dark:text-zinc-500 font-medium">
            {description}
          </span>
        </div>
        <div className="flex items-center gap-4">
          {children}
        </div>
      </div>
    </div>
  )
}

function Toggle({ checked, onChange }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
        checked ? 'bg-indigo-500' : 'bg-slate-200 dark:bg-zinc-800'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          checked ? 'translate-x-6' : 'translate-x-1'
        }`}
      />
    </button>
  )
}

function Settings({ initialSettings = {} }) {
  const [settings, setSettings] = useState({
    llmModel: 'qwen2.5-coder:14b',
    maxTokens: 512,
    timeout: 120,
    semanticThreshold: 0.85,
    saveHistory: true,
    storeRawRows: false,
    lookbackRows: 80,
    parserUrl: 'http://127.0.0.1:8003',
    theme: 'dark',
    language: 'ru',
    compactMode: false,
    ...initialSettings
  })

  const [saving, setSaving] = useState(false)

  const handleChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }

  const handleSave = () => {
    setSaving(true)
    // Simulate API sync
    setTimeout(() => {
      setSaving(false)
      window.alert('Протокол обновлен. Системные параметры синхронизированы.')
    }, 1200)
  }

  return (
    <div className="min-h-screen max-w-6xl mx-auto px-6 py-12 pb-32">
      <div className="flex items-center justify-between mb-16">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="h-1.5 w-1.5 rounded-full bg-indigo-500 animate-pulse" />
            <span className="text-[10px] font-black uppercase tracking-[0.4em] text-indigo-500">
              System Operations
            </span>
          </div>
          <h1 className="text-5xl font-black tracking-tighter text-slate-900 dark:text-white">
            Command <span className="text-indigo-500 italic">Protocol</span>
          </h1>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setSettings({
              llmModel: 'qwen2.5-coder:14b',
              maxTokens: 512,
              timeout: 120,
              semanticThreshold: 0.85,
              saveHistory: true,
              storeRawRows: false,
              lookbackRows: 80,
              parserUrl: 'http://127.0.0.1:8003',
              theme: 'dark',
              language: 'ru',
              compactMode: false
            })}
            className="flex items-center gap-2 px-6 py-3 rounded-2xl border border-slate-200 dark:border-zinc-800 text-sm font-bold text-slate-600 dark:text-zinc-400 hover:bg-slate-50 dark:hover:bg-zinc-800 transition-all"
          >
            <RotateCcw className="w-4 h-4" />
            Сброс
          </button>
          <button 
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-8 py-3 rounded-2xl bg-indigo-500 text-white text-sm font-black shadow-lg shadow-indigo-500/30 hover:bg-indigo-600 transition-all active:scale-95 disabled:grayscale"
          >
            {saving ? (
              <Activity className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saving ? 'Синхронизация...' : 'Применить'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* AI & STRATEGY */}
        <SettingsSection title="Интеллектуальный протокол" icon={Cpu}>
          <SettingItem 
            label="Модель LLM" 
            description="Основной аналитический движок для SQL синтеза"
          >
            <select 
              value={settings.llmModel}
              onChange={(e) => handleChange('llmModel', e.target.value)}
              className="bg-slate-100 dark:bg-zinc-800 border-none rounded-xl px-4 py-2 text-xs font-bold outline-none focus:ring-2 ring-indigo-500/50 transition-all"
            >
              <option value="qwen2.5-coder:14b">Qwen 2.5 Coder 14B</option>
              <option value="llama3.1:8b">Llama 3.1 8B</option>
              <option value="mistral:v0.3">Mistral v0.3</option>
            </select>
          </SettingItem>

          <SettingItem 
            label="Глубина ответа" 
            description="Максимальное количество токенов генерации"
          >
            <input 
              type="range" 
              min="256" 
              max="2048" 
              step="128"
              value={settings.maxTokens}
              onChange={(e) => handleChange('maxTokens', parseInt(e.target.value))}
              className="w-32 h-1.5 bg-slate-200 dark:bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-indigo-500"
            />
            <span className="text-[10px] font-black w-8">{settings.maxTokens}</span>
          </SettingItem>

          <SettingItem 
            label="Порог релевантности" 
            description="Минимальная уверенность семантического поиска"
          >
            <input 
              type="number" 
              min="0.1" 
              max="1.0" 
              step="0.05"
              value={settings.semanticThreshold}
              onChange={(e) => handleChange('semanticThreshold', parseFloat(e.target.value))}
              className="w-20 bg-slate-100 dark:bg-zinc-800 border-none rounded-xl px-3 py-1.5 text-xs font-black text-center outline-none"
            />
          </SettingItem>
        </SettingsSection>

        {/* DATA & PERSISTENCE */}
        <SettingsSection title="Тактика хранения" icon={Layers}>
          <SettingItem 
            label="Логирование запросов" 
            description="Сохранять историю AI-диалогов в базе данных"
          >
            <Toggle 
              checked={settings.saveHistory} 
              onChange={(val) => handleChange('saveHistory', val)} 
            />
          </SettingItem>

          <SettingItem 
            label="Архив RAW JSON" 
            description="Хранить оригинальные ответы парсера для отладки"
          >
            <Toggle 
              checked={settings.storeRawRows} 
              onChange={(val) => handleChange('storeRawRows', val)} 
            />
          </SettingItem>

          <SettingItem 
            label="Глубина регрессии" 
            description="Количество строк для контекстного анализа"
          >
            <input 
              type="number" 
              value={settings.lookbackRows}
              onChange={(e) => handleChange('lookbackRows', parseInt(e.target.value))}
              className="w-20 bg-slate-100 dark:bg-zinc-800 border-none rounded-xl px-3 py-1.5 text-xs font-black text-center outline-none"
            />
          </SettingItem>
        </SettingsSection>

        {/* NETWORK MATRIX */}
        <SettingsSection title="Сетевая матрица" icon={Globe}>
          <SettingItem 
            label="Ollama Node URL" 
            description="Адрес локального сервера инференса"
          >
            <div className="flex items-center gap-2 bg-slate-100 dark:bg-zinc-800 px-3 py-1.5 rounded-xl border border-transparent focus-within:border-indigo-500/50 transition-all">
              <Terminal className="w-3 h-3 text-slate-400" />
              <input 
                type="text" 
                value={settings.parserUrl}
                onChange={(e) => handleChange('parserUrl', e.target.value)}
                className="bg-transparent border-none text-[11px] font-bold outline-none w-48"
              />
            </div>
          </SettingItem>

          <div className="mt-4 p-4 rounded-2xl bg-slate-50 dark:bg-black/20 border border-slate-100 dark:border-zinc-800/50">
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Node Status</span>
              <div className="flex items-center gap-1.5">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                <span className="text-[9px] font-black text-emerald-500 uppercase">Online</span>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500/40" />
                <span className="text-[11px] font-bold text-slate-500 dark:text-zinc-400">Kaspi Parser</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500/40" />
                <span className="text-[11px] font-bold text-slate-500 dark:text-zinc-400">Halyk Node</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500/40" />
                <span className="text-[11px] font-bold text-slate-500 dark:text-zinc-400">Generic CSV</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-slate-300 dark:bg-zinc-700" />
                <span className="text-[11px] font-bold text-slate-400 dark:text-zinc-600 italic">Custom Node</span>
              </div>
            </div>
          </div>
        </SettingsSection>

        {/* INTERFACE PROTOCOL */}
        <SettingsSection title="Интерфейс протокола" icon={Zap}>
          <SettingItem 
            label="Локализация" 
            description="Язык операционной среды"
          >
            <div className="flex p-1 bg-slate-100 dark:bg-zinc-800 rounded-xl">
              <button 
                onClick={() => handleChange('language', 'ru')}
                className={`px-3 py-1 rounded-lg text-[10px] font-black transition-all ${settings.language === 'ru' ? 'bg-white dark:bg-zinc-700 shadow-sm text-indigo-500' : 'text-slate-400'}`}
              >
                RU
              </button>
              <button 
                onClick={() => handleChange('language', 'en')}
                className={`px-3 py-1 rounded-lg text-[10px] font-black transition-all ${settings.language === 'en' ? 'bg-white dark:bg-zinc-700 shadow-sm text-indigo-500' : 'text-slate-400'}`}
              >
                EN
              </button>
            </div>
          </SettingItem>

          <SettingItem 
            label="Плотность данных" 
            description="Компактный вид таблиц и списков"
          >
            <Toggle 
              checked={settings.compactMode} 
              onChange={(val) => handleChange('compactMode', val)} 
            />
          </SettingItem>

          <SettingItem 
            label="Режим Dark Ops" 
            description="Высококонтрастная темная тема"
          >
            <Toggle 
              checked={settings.theme === 'dark'} 
              onChange={(val) => handleChange('theme', val ? 'dark' : 'light')} 
            />
          </SettingItem>
        </SettingsSection>
      </div>
      
      <div className="mt-16 flex flex-col items-center">
        <div className="w-full h-px bg-gradient-to-r from-transparent via-slate-200 dark:via-zinc-800 to-transparent mb-8" />
        <p className="text-[10px] font-black uppercase tracking-[0.5em] text-slate-300 dark:text-zinc-700">
          FinAnalytica Intelligence Protocol v2.5.0-ENT
        </p>
      </div>
    </div>
  )
}

export default Settings
