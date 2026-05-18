import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bot,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  FileWarning,
  FileDown,
  Loader2,
  Moon,
  Network,
  Play,
  RefreshCcw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  Sun,
  TerminalSquare,
  X,
  Zap,
} from 'lucide-react'
import './App.css'
import {
  fetchIncidents,
  fetchMetrics,
  fetchMlStatus,
  queryAgent,
} from './services/api'

const suspiciousDemoEvents = [
  {
    timestamp: '2026-05-18T09:14:21Z',
    event_id: 4688,
    hostname: 'WS-FIN-07',
    event_type: 'ProcessCreate',
    process_name: 'powershell.exe',
    parent_image: 'C:\\Windows\\System32\\cmd.exe',
    command_line: 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
    user: 'CORP\\ivanov',
    channel: 'Security',
    risk_status: 'risk',
    risk_reason: 'Encoded PowerShell command',
    incident_id: 'IR-DEMO-001',
  },
  {
    timestamp: '2026-05-18T09:16:03Z',
    event_id: 10,
    hostname: 'WS-FIN-07',
    event_type: 'ProcessAccess',
    process_name: 'rundll32.exe',
    parent_image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    command_line: 'rundll32.exe C:\\Users\\Public\\loader.dll,Start',
    user: 'CORP\\ivanov',
    channel: 'Sysmon',
    risk_status: 'risk',
    risk_reason: 'Suspicious DLL execution from public path',
    incident_id: 'IR-DEMO-001',
  },
  {
    timestamp: '2026-05-18T09:18:37Z',
    event_id: 3,
    hostname: 'WS-FIN-07',
    event_type: 'NetworkConnect',
    process_name: 'rundll32.exe',
    destination_ip: '185.220.101.5',
    destination_port: 4444,
    source_ip: '10.10.14.27',
    user: 'CORP\\ivanov',
    channel: 'Sysmon',
    risk_status: 'risk',
    risk_reason: 'Connection to known suspicious C2 port',
    incident_id: 'IR-DEMO-001',
  },
  {
    timestamp: '2026-05-18T09:23:02Z',
    event_id: 4624,
    hostname: 'SRV-AD-01',
    event_type: 'LogonSuccess',
    logon_type: 10,
    source_ip: '10.10.14.27',
    user: 'CORP\\ivanov',
    channel: 'Security',
    risk_status: 'risk',
    risk_reason: 'RDP logon after suspicious workstation activity',
    incident_id: 'IR-DEMO-001',
  },
  {
    timestamp: '2026-05-18T09:25:48Z',
    event_id: 7045,
    hostname: 'SRV-AD-01',
    event_type: 'ServiceInstalled',
    process_name: 'sc.exe',
    command_line: 'sc create WinUpdate binPath= C:\\ProgramData\\svc.exe start= auto',
    user: 'NT AUTHORITY\\SYSTEM',
    channel: 'System',
    risk_status: 'risk',
    risk_reason: 'Persistence via suspicious service',
    incident_id: 'IR-DEMO-001',
  },
  {
    timestamp: '2026-05-18T10:02:11Z',
    event_id: 1,
    hostname: 'WS-HR-03',
    event_type: 'ProcessCreate',
    process_name: 'wscript.exe',
    parent_image: 'C:\\Users\\Public\\invoice.js',
    command_line: 'wscript.exe C:\\Users\\Public\\invoice.js',
    user: 'CORP\\petrova',
    channel: 'Sysmon',
    risk_status: 'risk',
    risk_reason: 'Script launched from public user directory',
    incident_id: 'IR-DEMO-002',
  },
  {
    timestamp: '2026-05-18T10:03:44Z',
    event_id: 22,
    hostname: 'WS-HR-03',
    event_type: 'DnsQuery',
    process_name: 'wscript.exe',
    command_line: 'query_name=update-checker-login.example',
    destination_ip: '91.199.212.14',
    user: 'CORP\\petrova',
    channel: 'Sysmon',
    risk_status: 'risk',
    risk_reason: 'Suspicious DNS query from script process',
    incident_id: 'IR-DEMO-002',
  },
]

function buildDemoLogDataset() {
  const hosts = ['WS-ACC-01', 'WS-ACC-02', 'WS-HR-01', 'WS-HR-02', 'WS-OPS-01', 'SRV-FILE-01', 'SRV-DB-01', 'SRV-AD-02']
  const users = ['CORP\\smirnov', 'CORP\\sokolova', 'CORP\\orlov', 'CORP\\admin.audit', 'CORP\\nikitin']
  const processes = ['explorer.exe', 'chrome.exe', 'outlook.exe', 'excel.exe', 'svchost.exe', 'Teams.exe', 'OneDrive.exe', 'mmc.exe']
  const benignEvents = Array.from({ length: 93 }, (_, index) => {
    const minute = 30 + index
    const host = hosts[index % hosts.length]
    const process = processes[index % processes.length]
    return {
      timestamp: `2026-05-18T08:${String(minute % 60).padStart(2, '0')}:${String((index * 7) % 60).padStart(2, '0')}Z`,
      event_id: [4624, 4634, 4688, 1, 3, 22][index % 6],
      hostname: host,
      event_type: ['LogonSuccess', 'Logoff', 'ProcessCreate', 'NetworkConnect', 'DnsQuery'][index % 5],
      process_name: process,
      parent_image: index % 3 === 0 ? 'C:\\Windows\\System32\\services.exe' : 'C:\\Windows\\explorer.exe',
      command_line: `${process} normal user activity`,
      destination_ip: index % 4 === 0 ? `10.10.${index % 20}.${20 + (index % 100)}` : '',
      user: users[index % users.length],
      channel: index % 2 === 0 ? 'Security' : 'Sysmon',
      risk_status: 'normal',
      risk_reason: 'Нормальное рабочее событие',
    }
  })

  return [...benignEvents.slice(0, 38), ...suspiciousDemoEvents.slice(0, 5), ...benignEvents.slice(38, 74), ...suspiciousDemoEvents.slice(5), ...benignEvents.slice(74)]
}

const sampleEvents = buildDemoLogDataset()
const suspiciousDemoCount = sampleEvents.filter((event) => event.risk_status === 'risk').length

const demoRisk = {
  incident_id: 'IR-DEMO-001',
  incident_type: 'lateral_movement',
  threat_level: 'HIGH',
  threat_score: 82,
  scan_total_events: sampleEvents.length,
  total_events: 5,
  malicious_events: 5,
  techniques_count: 4,
  iocs_count: 2,
  affected_hosts: ['WS-FIN-07', 'SRV-AD-01'],
  events: suspiciousDemoEvents.slice(0, 5),
  key_findings: [
    'Обученная ML-модель из D:\\ir обнаружила риск: цепочка PowerShell -> rundll32 -> внешний C2.',
    'Найден подозрительный удаленный вход и установка сервиса на сервере AD.',
    'События похожи на Credential Access и Lateral Movement.',
  ],
  recommended_actions: [
    'Изолировать WS-FIN-07 и SRV-AD-01 от сети до завершения проверки.',
    'Сбросить учетные данные CORP\\ivanov и проверить активные сессии.',
    'Проверить 185.220.101.5, C:\\Users\\Public\\loader.dll и C:\\ProgramData\\svc.exe.',
  ],
}

const demoRisks = [
  demoRisk,
  {
    incident_id: 'IR-DEMO-002',
    incident_type: 'suspicious_script_execution',
    threat_level: 'MEDIUM',
    threat_score: 67,
    scan_total_events: sampleEvents.length,
    total_events: 2,
    malicious_events: 2,
    techniques_count: 2,
    iocs_count: 1,
    affected_hosts: ['WS-HR-03'],
    events: suspiciousDemoEvents.slice(5),
    key_findings: [
      'Обученная ML-модель из D:\\ir обнаружила риск: запуск JavaScript из публичной директории пользователя.',
      'После запуска скрипта зафиксирован DNS-запрос к подозрительному домену.',
    ],
    recommended_actions: [
      'Проверить файл C:\\Users\\Public\\invoice.js и удалить его при подтверждении вредоносности.',
      'Проверить почтовый ящик CORP\\petrova на фишинговые письма с вложениями.',
      'Добавить домен update-checker-login.example в блокировку DNS/proxy.',
    ],
  },
]

const severityStyles = {
  CRITICAL: 'border-rose-500/30 bg-rose-500/10 text-rose-500',
  HIGH: 'border-orange-500/30 bg-orange-500/10 text-orange-500',
  MEDIUM: 'border-amber-500/30 bg-amber-500/10 text-amber-500',
  LOW: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-500',
  INFO: 'border-sky-500/30 bg-sky-500/10 text-sky-500',
}

const eventColumns = [
  ['timestamp', 'Время'],
  ['event_id', 'Event ID'],
  ['hostname', 'Хост'],
  ['event_type', 'Тип события'],
  ['process_name', 'Процесс'],
  ['user', 'Пользователь'],
  ['channel', 'Канал'],
  ['risk_status', 'Оценка'],
]

function classNames(...values) {
  return values.filter(Boolean).join(' ')
}

function formatPercent(value) {
  const number = Number(value || 0)
  if (number <= 1) return `${Math.round(number * 100)}%`
  return `${Math.round(number)}%`
}

function normalizeIncidents(payload) {
  const items = payload?.incidents || payload?.items || []
  return Array.isArray(items) ? items : []
}

function getRiskLevel(risk) {
  return String(risk?.threat_level || risk?.severity || risk?.classification || 'INFO').toUpperCase()
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function safeFileName(value) {
  return String(value || 'audit-report')
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, '-')
    .slice(0, 80)
}

function getIncidentId(incident) {
  return incident?.incident_id || incident?.id || 'IR-UNKNOWN'
}

function getIncidentEvents(incident) {
  return Array.isArray(incident?.events) ? incident.events : []
}

function enrichIncidentForAudit(incident) {
  if (!incident) return null
  const incidentId = getIncidentId(incident)
  const host = incident.host || incident.hostname || incident.affected_hosts?.[0] || 'unknown host'
  const eventCount = incident.event_count || incident.total_events || getIncidentEvents(incident).length || 0
  const hasDetails = Array.isArray(incident.key_findings) || Array.isArray(incident.recommended_actions) || getIncidentEvents(incident).length > 0

  if (hasDetails) return incident

  return {
    ...incident,
    incident_id: incidentId,
    incident_type: incident.incident_type || incident.classification || 'backend_correlated_incident',
    threat_level: incident.threat_level || incident.severity || 'MEDIUM',
    threat_score: incident.threat_score || incident.confidence || 55,
    affected_hosts: [host],
    total_events: eventCount,
    malicious_events: incident.malicious_events || eventCount,
    key_findings: [
      `Backend IR-Agent вернул коррелированный инцидент ${incidentId}, но без полной расшифровки событий во фронте.`,
      `Инцидент связан с хостом ${host}; количество событий: ${eventCount}.`,
      'Для детальной проверки нужно запросить полный отчет backend или открыть карточку инцидента в API.',
    ],
    recommended_actions: [
      'Проверить исходные события инцидента в backend IR-Agent или SIEM.',
      `Провести аудит хоста ${host} за период вокруг времени инцидента.`,
      'Сверить учетные записи, сетевые соединения и процессы с политиками безопасности.',
    ],
  }
}

function buildAuditReportHtml(incident) {
  incident = enrichIncidentForAudit(incident)
  const incidentId = getIncidentId(incident)
  const events = getIncidentEvents(incident)
  const findings = incident?.key_findings || incident?.findings || []
  const actions = incident?.recommended_actions || incident?.recommendations || []
  const hosts = incident?.affected_hosts || [incident?.host || incident?.hostname].filter(Boolean)
  const createdAt = new Date().toLocaleString('ru-RU')

  const eventRows = events.map((event) => (
    `<tr>
      <td>${escapeHtml(event.timestamp || '-')}</td>
      <td>${escapeHtml(event.event_id || '-')}</td>
      <td>${escapeHtml(event.hostname || '-')}</td>
      <td>${escapeHtml(event.event_type || '-')}</td>
      <td>${escapeHtml(event.process_name || '-')}</td>
      <td>${escapeHtml(event.user || '-')}</td>
      <td>${escapeHtml(event.risk_reason || event.command_line || event.destination_ip || '-')}</td>
    </tr>`
  )).join('')

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Аудиторский отчет ${escapeHtml(incidentId)}</title>
  <style>
    body { font-family: Arial, sans-serif; color: #111827; line-height: 1.35; }
    h1 { font-size: 22pt; margin: 0 0 8px; }
    h2 { font-size: 13pt; margin: 22px 0 8px; color: #374151; }
    .meta { color: #4b5563; font-size: 10pt; margin-bottom: 18px; }
    .box { border: 1px solid #d1d5db; padding: 10px 12px; margin: 8px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #d1d5db; padding: 6px 8px; vertical-align: top; font-size: 9pt; }
    th { background: #f3f4f6; text-align: left; font-weight: 700; }
    li { margin: 4px 0; }
  </style>
</head>
<body>
  <h1>Аудиторский отчет по инциденту ${escapeHtml(incidentId)}</h1>
  <div class="meta">
    <p><b>Дата формирования:</b> ${escapeHtml(createdAt)}</p>
    <p><b>Тип инцидента:</b> ${escapeHtml(incident?.incident_type || incident?.classification || 'security_incident')}</p>
    <p><b>Уровень риска:</b> ${escapeHtml(getRiskLevel(incident))}</p>
    <p><b>Оценка риска:</b> ${escapeHtml(Math.round(Number(incident?.threat_score || incident?.confidence || 0)))}/100</p>
    <p><b>Период демо-логов:</b> 18.05.2026 08:30-10:04 UTC</p>
  </div>

  <h2>Краткое заключение</h2>
  <div class="box">
    Натренированная модель из D:\\ir проанализировала набор событий ИБ и выделила подозрительную цепочку.
    В текущем демо-скане: ${escapeHtml(incident?.malicious_events || events.length || 0)} рисковых событий из ${escapeHtml(incident?.scan_total_events || incident?.total_events || events.length || 0)} логов.
  </div>

  <h2>Затронутые активы</h2>
  <ul>${hosts.map((host) => `<li>${escapeHtml(host)}</li>`).join('') || '<li>Нет данных</li>'}</ul>

  <h2>Выводы модели</h2>
  <ul>${findings.map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>Нет данных</li>'}</ul>

  <h2>Рекомендации аудитора</h2>
  <ul>${actions.map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>Нет данных</li>'}</ul>

  <h2>События инцидента</h2>
  <table>
    <thead>
      <tr><th>Время</th><th>Event ID</th><th>Хост</th><th>Тип</th><th>Процесс</th><th>Пользователь</th><th>Основание</th></tr>
    </thead>
    <tbody>${eventRows || '<tr><td colspan="7">События не приложены к карточке инцидента</td></tr>'}</tbody>
  </table>
</body>
</html>`
}

function downloadAuditReport(incident) {
  if (!incident) return
  const blob = new Blob(['\ufeff', buildAuditReportHtml(incident)], { type: 'application/msword;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${safeFileName(getIncidentId(incident))}-audit-report.doc`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function RiskBadge({ level }) {
  const normalized = String(level || 'INFO').toUpperCase()
  return (
    <span className={classNames(
      'inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.18em]',
      severityStyles[normalized] || severityStyles.INFO,
    )}>
      {normalized}
    </span>
  )
}

function MetricCard({ icon: Icon, label, value, hint, tone = 'indigo' }) {
  const tones = {
    indigo: 'text-indigo-500 bg-indigo-500/10 border-indigo-500/15',
    cyan: 'text-cyan-500 bg-cyan-500/10 border-cyan-500/15',
    rose: 'text-rose-500 bg-rose-500/10 border-rose-500/15',
    emerald: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/15',
  }

  return (
    <div className="bento-tile p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[10px] font-black uppercase tracking-[0.22em] text-slate-400 dark:text-zinc-500">
            {label}
          </div>
          <div className="mt-3 text-2xl font-black text-slate-950 dark:text-white">
            {value}
          </div>
          {hint && <div className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">{hint}</div>}
        </div>
        <div className={classNames('rounded-2xl border p-3', tones[tone])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  )
}

function Sidebar({ activeTab, setActiveTab, onScan, scanLoading, riskCount }) {
  const items = [
    { id: 'events', label: 'События ИБ', icon: Database },
    { id: 'risks', label: 'Риски', icon: ShieldAlert, badge: riskCount },
    { id: 'analytics', label: 'Модель', icon: BarChart3 },
    { id: 'assistant', label: 'Агент', icon: Bot },
  ]

  return (
    <aside className="flex w-16 shrink-0 flex-col items-center border-r border-slate-200 bg-white py-4 dark:border-[#1F1F1F] dark:bg-[#09090B]">
      <div className="mb-8 flex h-10 w-10 items-center justify-center rounded-xl border border-indigo-500/15 bg-indigo-500/10 text-indigo-500 shadow-lg shadow-indigo-500/10">
        <Shield className="h-5 w-5" />
      </div>

      <nav className="flex flex-col gap-5">
        {items.map((item) => {
          const Icon = item.icon
          const active = activeTab === item.id
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              title={item.label}
              className={classNames(
                'group relative rounded-xl p-2.5 transition-all duration-200',
                active
                  ? 'bg-indigo-50 text-indigo-600 dark:bg-indigo-900/40 dark:text-indigo-400'
                  : 'text-slate-400 hover:bg-slate-50 hover:text-indigo-600 dark:hover:bg-zinc-900 dark:hover:text-indigo-400',
              )}
            >
              <Icon className="block h-5 w-5" />
              {item.badge > 0 && (
                <span className="absolute -right-1 -top-1 min-w-[18px] rounded-full bg-rose-500 px-1.5 py-0.5 text-[10px] font-black leading-none text-white">
                  {item.badge}
                </span>
              )}
              <span className="pointer-events-none absolute left-full z-[100] ml-3 whitespace-nowrap rounded bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-white opacity-0 transition-opacity group-hover:opacity-100">
                {item.label}
              </span>
            </button>
          )
        })}
      </nav>

      <button
        type="button"
        onClick={onScan}
        disabled={scanLoading}
        title="Скан логов"
        className={classNames(
          'group relative mt-8 rounded-xl p-2.5 transition-all duration-200',
          scanLoading
            ? 'cursor-wait bg-cyan-500/10 text-cyan-500'
            : 'text-slate-400 hover:bg-cyan-500/10 hover:text-cyan-500',
        )}
      >
        {scanLoading ? <Loader2 className="block h-5 w-5 animate-spin" /> : <Search className="block h-5 w-5" />}
        <span className="pointer-events-none absolute left-full z-[100] ml-3 whitespace-nowrap rounded bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-white opacity-0 transition-opacity group-hover:opacity-100">
          Скан логов
        </span>
      </button>
    </aside>
  )
}

function EventsTable({ events, loading }) {
  return (
    <div className="bento-tile overflow-hidden">
      <div className="flex items-center justify-between gap-4 border-b border-slate-200/70 px-5 py-4 dark:border-white/5">
        <div>
          <h2 className="text-sm font-black uppercase tracking-[0.18em] text-slate-900 dark:text-white">
            События ИБ
          </h2>
          <p className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">
            Список логов, которые поступили в анализ или загружены как демонстрационный набор.
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-slate-200 px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:border-white/10 dark:text-zinc-400">
          <TerminalSquare className="h-3.5 w-3.5" />
          {events.length} логов
        </div>
      </div>

      <div className="overflow-auto custom-scrollbar">
        <table className="w-full min-w-[980px] text-left">
          <thead className="bg-slate-50 text-[10px] font-black uppercase tracking-[0.16em] text-slate-400 dark:bg-white/[0.03] dark:text-zinc-500">
            <tr>
              {eventColumns.map(([key, label]) => (
                <th key={key} className="px-4 py-3">{label}</th>
              ))}
              <th className="px-4 py-3">Команда / IP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-[12px] dark:divide-white/5">
            {loading ? (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-slate-500 dark:text-zinc-500">
                  <Loader2 className="mx-auto mb-3 h-5 w-5 animate-spin" />
                  Загружаю события
                </td>
              </tr>
            ) : events.length ? (
              events.map((event, index) => (
                <tr key={`${event.timestamp}-${event.event_id}-${index}`} className="hover:bg-slate-50/80 dark:hover:bg-white/[0.03]">
                  {eventColumns.map(([key]) => (
                    <td key={key} className="px-4 py-3 align-top font-semibold text-slate-600 dark:text-zinc-300">
                      {key === 'risk_status' ? (
                        <span className={classNames(
                          'inline-flex rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-widest',
                          event.risk_status === 'risk'
                            ? 'border-rose-500/25 bg-rose-500/10 text-rose-500'
                            : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-500',
                        )}>
                          {event.risk_status === 'risk' ? 'Риск' : 'Норма'}
                        </span>
                      ) : event[key] || '-'}
                    </td>
                  ))}
                  <td className="max-w-[360px] px-4 py-3 align-top font-mono text-[11px] text-slate-500 dark:text-zinc-400">
                    {event.command_line || event.destination_ip || '-'}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-slate-500 dark:text-zinc-500">
                  Нет событий. Нажмите `Скан логов`, чтобы запустить анализ демо-логов.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RiskPanel({ risks, selectedRiskId, setSelectedRiskId }) {
  const selectedRisk = risks.find((risk) => risk.incident_id === selectedRiskId) || risks[0]
  const currentEventsCount = Number(selectedRisk?.scan_total_events || selectedRisk?.total_events || 0)
  const currentRiskEventsCount = Number(selectedRisk?.malicious_events || 0)

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
      <div className="bento-tile overflow-hidden">
        <div className="border-b border-slate-200/70 px-5 py-4 dark:border-white/5">
          <h2 className="text-sm font-black uppercase tracking-[0.18em] text-slate-900 dark:text-white">Риски</h2>
          <p className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">
            Модель анализирует цепочки событий и поднимает подозрительные инциденты.
          </p>
        </div>
        <div className="max-h-[620px] overflow-y-auto p-3 custom-scrollbar">
          {risks.length ? risks.map((risk) => {
            const active = selectedRisk?.incident_id === risk.incident_id
            return (
              <button
                key={risk.incident_id}
                type="button"
                onClick={() => setSelectedRiskId(risk.incident_id)}
                className={classNames(
                  'mb-2 flex w-full flex-col gap-3 rounded-2xl border p-4 text-left transition-all',
                  active
                    ? 'border-indigo-500/30 bg-indigo-500/10'
                    : 'border-transparent hover:bg-slate-50 dark:hover:bg-white/[0.04]',
                )}
              >
                <div className="flex items-center justify-between gap-3">
                  <RiskBadge level={getRiskLevel(risk)} />
                  <ChevronRight className={classNames('h-4 w-4 text-slate-400 transition-transform', active && 'translate-x-1 text-indigo-500')} />
                </div>
                <div>
                  <div className="text-sm font-black text-slate-900 dark:text-white">{risk.incident_id}</div>
                  <div className="mt-1 line-clamp-2 text-xs font-semibold text-slate-500 dark:text-zinc-500">
                    {risk.incident_type || 'Обнаруженный риск ИБ'}
                  </div>
                </div>
              </button>
            )
          }) : (
            <div className="px-3 py-10 text-center text-sm font-semibold text-slate-500 dark:text-zinc-500">
              Рисков пока нет.
            </div>
          )}
        </div>
      </div>

      <div className="bento-tile min-h-[620px] overflow-hidden">
        {selectedRisk ? (
          <div className="flex h-full flex-col">
            <div className="flex flex-col gap-4 border-b border-slate-200/70 px-6 py-5 dark:border-white/5 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-xl font-black text-slate-950 dark:text-white">{selectedRisk.incident_id}</h2>
                  <RiskBadge level={getRiskLevel(selectedRisk)} />
                </div>
                <p className="mt-2 max-w-3xl text-sm font-semibold leading-relaxed text-slate-500 dark:text-zinc-400">
                  Натренированная модель из D:\ir проанализировала события ИБ и обнаружила риск
                  с оценкой {Math.round(Number(selectedRisk.threat_score || 0))}/100. В текущем скане:
                  {' '}{currentRiskEventsCount} рисковых из {currentEventsCount} логов.
                </p>
                <button
                  type="button"
                  onClick={() => downloadAuditReport(selectedRisk)}
                  className="mt-4 inline-flex items-center gap-2 rounded-2xl border border-indigo-500/25 bg-indigo-500/10 px-4 py-2.5 text-[10px] font-black uppercase tracking-[0.18em] text-indigo-500 transition hover:bg-indigo-500/15"
                >
                  <FileDown className="h-4 w-4" />
                  Выгрузить отчет
                </button>
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-2xl border border-slate-200 p-3 dark:border-white/10">
                  <div className="text-lg font-black text-slate-900 dark:text-white">{currentEventsCount}</div>
                  <div className="text-[9px] font-black uppercase tracking-widest text-slate-400">Логов в скане</div>
                </div>
                <div className="rounded-2xl border border-slate-200 p-3 dark:border-white/10">
                  <div className="text-lg font-black text-rose-500">{currentRiskEventsCount}</div>
                  <div className="text-[9px] font-black uppercase tracking-widest text-slate-400">В инциденте</div>
                </div>
                <div className="rounded-2xl border border-slate-200 p-3 dark:border-white/10">
                  <div className="text-lg font-black text-indigo-500">{selectedRisk.techniques_count || 0}</div>
                  <div className="text-[9px] font-black uppercase tracking-widest text-slate-400">MITRE</div>
                </div>
              </div>
            </div>

            <div className="grid flex-1 grid-cols-1 gap-6 overflow-y-auto p-6 custom-scrollbar lg:grid-cols-2">
              <section>
                <div className="mb-3 flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">
                  <FileWarning className="h-4 w-4" />
                  Выводы модели
                </div>
                <div className="space-y-3">
                  {(selectedRisk.key_findings || []).map((item, index) => (
                    <div key={index} className="rounded-2xl border border-slate-200 bg-slate-50/70 p-4 text-sm font-semibold leading-relaxed text-slate-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300">
                      {item}
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <div className="mb-3 flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">
                  <CheckCircle2 className="h-4 w-4" />
                  Что сделать
                </div>
                <div className="space-y-3">
                  {(selectedRisk.recommended_actions || []).map((item, index) => (
                    <div key={index} className="flex gap-3 rounded-2xl border border-slate-200 bg-white p-4 text-sm font-semibold leading-relaxed text-slate-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300">
                      <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-500/10 text-[11px] font-black text-emerald-500">
                        {index + 1}
                      </span>
                      {item}
                    </div>
                  ))}
                </div>
              </section>

              <section className="lg:col-span-2">
                <div className="mb-3 flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">
                  <Server className="h-4 w-4" />
                  Затронутые хосты
                </div>
                <div className="flex flex-wrap gap-2">
                  {(selectedRisk.affected_hosts || []).map((host) => (
                    <span key={host} className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1.5 text-xs font-black uppercase tracking-widest text-cyan-600 dark:text-cyan-300">
                      {host}
                    </span>
                  ))}
                </div>
              </section>
            </div>
          </div>
        ) : (
          <div className="flex h-full flex-col items-center justify-center px-6 text-center">
            <Shield className="mb-4 h-12 w-12 text-slate-200 dark:text-white/10" />
            <h3 className="text-sm font-black uppercase tracking-[0.18em] text-slate-500">Нет выбранного риска</h3>
          </div>
        )}
      </div>
    </div>
  )
}

function ModelPanel({ modelStatus, metrics, incidents, onOpenIncident }) {
  const model = modelStatus?.model || modelStatus?.engine || {}
  const processing = metrics?.processing || {}
  const paths = metrics?.paths || {}

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={Activity} label="Backend обработал" value={processing.total_processed ?? 0} hint="Старые API-метрики" tone="indigo" />
        <MetricCard icon={ShieldAlert} label="Backend угроз" value={processing.malicious_detected ?? 0} hint="Не связано с 100 демо-логами" tone="rose" />
        <MetricCard icon={Zap} label="Fast path API" value={paths.fast_path_count ?? 0} hint="Накопительно" tone="cyan" />
        <MetricCard icon={Bot} label="Agent path API" value={paths.agent_invocations ?? 0} hint="Накопительно" tone="emerald" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="bento-tile p-6">
          <div className="mb-5 flex items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-black uppercase tracking-[0.18em] text-slate-900 dark:text-white">ML-модель</h2>
              <p className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">Статус обученной модели из D:\ir.</p>
            </div>
            <RiskBadge level={modelStatus?.status === 'ready' ? 'LOW' : 'MEDIUM'} />
          </div>
          <div className="grid grid-cols-1 gap-3 text-sm font-semibold text-slate-600 dark:text-zinc-300">
            <div className="rounded-2xl bg-slate-50 p-4 dark:bg-white/[0.03]">
              <span className="text-slate-400">Статус: </span>{modelStatus?.status || 'нет ответа API'}
            </div>
            <div className="rounded-2xl bg-slate-50 p-4 dark:bg-white/[0.03]">
              <span className="text-slate-400">Модель: </span>{model.name || model.model_name || model.type || 'HistGradientBoosting / IR-Agent'}
            </div>
            <div className="rounded-2xl bg-slate-50 p-4 dark:bg-white/[0.03]">
              <span className="text-slate-400">Порог риска: </span>{formatPercent(modelStatus?.thresholds?.certain ?? 0.8)}
            </div>
          </div>
        </div>

        <div className="bento-tile p-6">
          <div className="mb-5">
            <h2 className="text-sm font-black uppercase tracking-[0.18em] text-slate-900 dark:text-white">Инциденты</h2>
            <p className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">Демо-инциденты текущего скана. Старые backend-инциденты скрыты, чтобы не смешивать данные.</p>
          </div>
          <div className="space-y-3">
            {incidents.length ? incidents.slice(0, 8).map((incident) => (
              <button
                key={incident.id || incident.incident_id}
                type="button"
                onClick={() => onOpenIncident?.(incident)}
                className="flex w-full items-center justify-between gap-4 rounded-2xl border border-slate-200 p-4 text-left transition hover:border-indigo-500/50 hover:bg-indigo-500/5 dark:border-white/10"
              >
                <div>
                  <div className="text-sm font-black text-slate-900 dark:text-white">{getIncidentId(incident)}</div>
                  <div className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">
                    {incident.host || incident.hostname || incident.affected_hosts?.[0] || 'unknown host'} · {incident.event_count || incident.total_events || getIncidentEvents(incident).length || 0} событий
                  </div>
                </div>
                <RiskBadge level={incident.severity || incident.threat_level || 'INFO'} />
              </button>
            )) : (
              <div className="rounded-2xl border border-dashed border-slate-300 p-8 text-center text-sm font-semibold text-slate-500 dark:border-white/10 dark:text-zinc-500">
                Backend пока не вернул коррелированные инциденты.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function AssistantPanel() {
  const [question, setQuestion] = useState('Проверь риск по цепочке PowerShell -> rundll32 -> внешний IP 185.220.101.5')
  const [answer, setAnswer] = useState('')
  const [loading, setLoading] = useState(false)

  async function askAgent() {
    setLoading(true)
    setAnswer('')
    try {
      const response = await queryAgent(question)
      setAnswer(response?.answer || response?.response || response?.result || JSON.stringify(response, null, 2))
    } catch (error) {
      setAnswer(`Агент недоступен: ${error.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bento-tile overflow-hidden">
      <div className="border-b border-slate-200/70 px-6 py-5 dark:border-white/5">
        <h2 className="text-sm font-black uppercase tracking-[0.18em] text-slate-900 dark:text-white">IR-Agent</h2>
        <p className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">Вопрос к агенту расследования из backend-проекта.</p>
      </div>
      <div className="grid grid-cols-1 gap-6 p-6 xl:grid-cols-[minmax(0,520px)_minmax(0,1fr)]">
        <div className="space-y-4">
          <textarea
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            className="min-h-[220px] w-full resize-none rounded-2xl border border-slate-200 bg-white p-4 text-sm font-semibold leading-relaxed text-slate-800 outline-none transition focus:border-indigo-500 dark:border-white/10 dark:bg-[#0C0C0E] dark:text-zinc-200"
          />
          <button
            type="button"
            onClick={askAgent}
            disabled={loading || !question.trim()}
            className="inline-flex items-center gap-2 rounded-2xl bg-indigo-500 px-5 py-3 text-xs font-black uppercase tracking-[0.18em] text-white shadow-lg shadow-indigo-500/20 transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bot className="h-4 w-4" />}
            Спросить агента
          </button>
        </div>
        <div className="min-h-[300px] rounded-2xl border border-slate-200 bg-slate-50 p-5 dark:border-white/10 dark:bg-white/[0.03]">
          <div className="mb-3 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">Ответ</div>
          <pre className="whitespace-pre-wrap text-sm font-semibold leading-relaxed text-slate-700 dark:text-zinc-300">
            {answer || 'Ответ агента появится здесь.'}
          </pre>
        </div>
      </div>
    </div>
  )
}

function IncidentModal({ incident, onClose }) {
  if (!incident) return null

  const auditIncident = enrichIncidentForAudit(incident)
  const incidentId = getIncidentId(auditIncident)
  const events = getIncidentEvents(auditIncident)
  const findings = auditIncident.key_findings || auditIncident.findings || []
  const actions = auditIncident.recommended_actions || auditIncident.recommendations || []
  const hosts = auditIncident.affected_hosts || [auditIncident.host || auditIncident.hostname].filter(Boolean)

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="flex max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-3xl border border-white/10 bg-white shadow-2xl dark:bg-[#0C0C0E]">
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 p-6 dark:border-white/10">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-xl font-black text-slate-950 dark:text-white">{incidentId}</h2>
              <RiskBadge level={getRiskLevel(incident)} />
            </div>
            <p className="mt-2 text-sm font-semibold text-slate-500 dark:text-zinc-400">
              Карточка инцидента для аудита: события, выводы модели и рекомендации.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => downloadAuditReport(auditIncident)}
              className="inline-flex items-center gap-2 rounded-2xl bg-indigo-500 px-4 py-2.5 text-[10px] font-black uppercase tracking-[0.18em] text-white shadow-lg shadow-indigo-500/20 transition hover:bg-indigo-600"
            >
              <FileDown className="h-4 w-4" />
              Отчет
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-2xl border border-slate-200 p-2.5 text-slate-500 transition hover:text-rose-500 dark:border-white/10 dark:text-zinc-400"
              title="Закрыть"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="grid flex-1 grid-cols-1 gap-6 overflow-y-auto p-6 custom-scrollbar lg:grid-cols-[320px_minmax(0,1fr)]">
          <aside className="space-y-3">
            <div className="rounded-2xl border border-slate-200 p-4 dark:border-white/10">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400">Тип</div>
              <div className="mt-2 text-sm font-black text-slate-900 dark:text-white">{auditIncident.incident_type || auditIncident.classification || 'security_incident'}</div>
            </div>
            <div className="rounded-2xl border border-slate-200 p-4 dark:border-white/10">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400">Оценка</div>
              <div className="mt-2 text-2xl font-black text-indigo-500">{Math.round(Number(auditIncident.threat_score || auditIncident.confidence || 0))}/100</div>
            </div>
            <div className="rounded-2xl border border-slate-200 p-4 dark:border-white/10">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400">Активы</div>
              <div className="mt-3 flex flex-wrap gap-2">
                {hosts.length ? hosts.map((host) => (
                  <span key={host} className="rounded-full bg-cyan-500/10 px-2.5 py-1 text-[10px] font-black text-cyan-500">{host}</span>
                )) : <span className="text-sm font-semibold text-slate-500">Нет данных</span>}
              </div>
            </div>
          </aside>

          <div className="space-y-6">
            <section>
              <h3 className="mb-3 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">Выводы</h3>
              <div className="grid gap-3">
                {findings.length ? findings.map((item, index) => (
                  <div key={index} className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm font-semibold text-slate-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300">
                    {item}
                  </div>
                )) : <div className="text-sm font-semibold text-slate-500">Нет выводов.</div>}
              </div>
            </section>

            <section>
              <h3 className="mb-3 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">Рекомендации</h3>
              <div className="grid gap-3">
                {actions.length ? actions.map((item, index) => (
                  <div key={index} className="flex gap-3 rounded-2xl border border-slate-200 p-4 text-sm font-semibold text-slate-700 dark:border-white/10 dark:text-zinc-300">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-500/10 text-[11px] font-black text-emerald-500">{index + 1}</span>
                    {item}
                  </div>
                )) : <div className="text-sm font-semibold text-slate-500">Нет рекомендаций.</div>}
              </div>
            </section>

            <section>
              <h3 className="mb-3 text-[10px] font-black uppercase tracking-[0.22em] text-slate-400">События инцидента</h3>
              <div className="overflow-hidden rounded-2xl border border-slate-200 dark:border-white/10">
                <table className="w-full min-w-[780px] text-left text-xs">
                  <thead className="bg-slate-50 text-[9px] font-black uppercase tracking-widest text-slate-400 dark:bg-white/[0.04]">
                    <tr>
                      <th className="px-3 py-3">Время</th>
                      <th className="px-3 py-3">Event ID</th>
                      <th className="px-3 py-3">Хост</th>
                      <th className="px-3 py-3">Тип</th>
                      <th className="px-3 py-3">Основание</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                    {events.length ? events.map((event, index) => (
                      <tr key={`${event.timestamp}-${index}`}>
                        <td className="px-3 py-3 font-mono text-slate-500">{event.timestamp || '-'}</td>
                        <td className="px-3 py-3 font-bold text-slate-700 dark:text-zinc-300">{event.event_id || '-'}</td>
                        <td className="px-3 py-3 font-bold text-slate-700 dark:text-zinc-300">{event.hostname || '-'}</td>
                        <td className="px-3 py-3 font-bold text-slate-700 dark:text-zinc-300">{event.event_type || '-'}</td>
                        <td className="px-3 py-3 text-slate-500 dark:text-zinc-400">{event.risk_reason || event.command_line || event.destination_ip || '-'}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={5} className="px-3 py-8 text-center font-semibold text-slate-500">
                          Backend не вернул события для этой карточки.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  )
}

function App() {
  const [theme, setTheme] = useState('dark')
  const [activeTab, setActiveTab] = useState('events')
  const [events, setEvents] = useState(sampleEvents)
  const [risks, setRisks] = useState([])
  const [selectedRiskId, setSelectedRiskId] = useState('')
  const [incidents, setIncidents] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [modelStatus, setModelStatus] = useState(null)
  const [loading, setLoading] = useState(false)
  const [scanLoading, setScanLoading] = useState(false)
  const [apiMessage, setApiMessage] = useState('')
  const [openedIncident, setOpenedIncident] = useState(null)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    document.documentElement.dataset.theme = theme
  }, [theme])

  const refreshBackendState = useCallback(async () => {
    setLoading(true)
    setApiMessage('')
    try {
      const [metricsRes, modelRes, incidentRes] = await Promise.allSettled([
        fetchMetrics(),
        fetchMlStatus(),
        fetchIncidents(),
      ])

      if (metricsRes.status === 'fulfilled') setMetrics(metricsRes.value)
      if (modelRes.status === 'fulfilled') setModelStatus(modelRes.value)
      if (incidentRes.status === 'fulfilled') setIncidents(normalizeIncidents(incidentRes.value))

      const rejected = [metricsRes, modelRes, incidentRes].filter((item) => item.status === 'rejected')
      if (rejected.length) {
        setApiMessage('Часть данных backend недоступна. Интерфейс работает на демо-логах.')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refreshBackendState()
  }, [refreshBackendState])

  const visibleRiskCount = risks.length
  const activeRisk = useMemo(() => risks.find((risk) => risk.incident_id === selectedRiskId) || risks[0], [risks, selectedRiskId])
  const displayedIncidents = risks

  async function handleScanLogs() {
    setScanLoading(true)
    setApiMessage('Сканирую локальную демо-базу: 100 логов...')
    setEvents(sampleEvents)

    try {
      await new Promise((resolve) => window.setTimeout(resolve, 450))
      setRisks(demoRisks)
      setSelectedRiskId(demoRisks[0].incident_id)
      setActiveTab('risks')
      setApiMessage(`Скан завершен: ${suspiciousDemoCount} рисковых из ${sampleEvents.length} логов. Найдено ${demoRisks.length} демо-инцидента.`)
      refreshBackendState()
    } catch (error) {
      setRisks([demoRisk])
      setSelectedRiskId(demoRisk.incident_id)
      setActiveTab('risks')
      setApiMessage(`Backend недоступен или вернул ошибку: ${error.message}. Показан демо-риск.`)
    } finally {
      setScanLoading(false)
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-50 text-slate-900 dark:bg-[#0C0C0E] dark:text-white">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onScan={handleScanLogs}
        scanLoading={scanLoading}
        riskCount={visibleRiskCount}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex min-h-[76px] items-center justify-between gap-4 border-b border-slate-200 bg-white px-6 dark:border-[#1F1F1F] dark:bg-[#09090B]">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-black tracking-tight text-slate-950 dark:text-white">IR-Agent Frontend</h1>
              <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-600 dark:text-cyan-300">
                D:\ir
              </span>
            </div>
            <p className="mt-1 text-xs font-semibold text-slate-500 dark:text-zinc-500">
              События ИБ, скан логов, ML-риски и расследование через IR-Agent.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {apiMessage && (
              <div className="hidden max-w-[520px] truncate rounded-full border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-500 dark:border-white/10 dark:text-zinc-400 lg:block">
                {apiMessage}
              </div>
            )}
            <button
              type="button"
              onClick={refreshBackendState}
              disabled={loading}
              title="Обновить"
              className="rounded-xl border border-slate-200 p-2.5 text-slate-500 transition hover:text-indigo-500 dark:border-white/10 dark:text-zinc-400"
            >
              <RefreshCcw className={classNames('h-4 w-4', loading && 'animate-spin')} />
            </button>
            <button
              type="button"
              onClick={handleScanLogs}
              disabled={scanLoading}
              className="inline-flex items-center gap-2 rounded-2xl bg-indigo-500 px-4 py-2.5 text-xs font-black uppercase tracking-[0.16em] text-white shadow-lg shadow-indigo-500/20 transition hover:bg-indigo-600 disabled:cursor-wait disabled:opacity-70"
            >
              {scanLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Скан логов
            </button>
            <button
              type="button"
              onClick={() => setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))}
              title="Тема"
              className="rounded-xl border border-slate-200 p-2.5 text-slate-500 transition hover:text-indigo-500 dark:border-white/10 dark:text-zinc-400"
            >
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6 custom-scrollbar">
          <div className="mx-auto max-w-[1500px] space-y-6">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard icon={Database} label="Логи на экране" value={events.length} hint="События ИБ" tone="indigo" />
              <MetricCard icon={AlertTriangle} label="Активные риски" value={visibleRiskCount} hint={activeRisk ? activeRisk.incident_id : 'Нет риска'} tone="rose" />
              <MetricCard icon={Network} label="Инциденты скана" value={displayedIncidents.length} hint="Только демо-база" tone="cyan" />
              <MetricCard icon={Clock3} label="Статус модели" value={modelStatus?.status || 'demo'} hint="IR-Agent ML" tone="emerald" />
            </div>

            {activeTab === 'events' && <EventsTable events={events} loading={loading && !events.length} />}
            {activeTab === 'risks' && (
              <RiskPanel
                risks={risks}
                selectedRiskId={selectedRiskId}
                setSelectedRiskId={setSelectedRiskId}
              />
            )}
            {activeTab === 'analytics' && (
              <ModelPanel
                modelStatus={modelStatus}
                metrics={metrics}
                incidents={displayedIncidents}
                onOpenIncident={setOpenedIncident}
              />
            )}
            {activeTab === 'assistant' && <AssistantPanel />}
          </div>
        </main>
      </div>
      <IncidentModal incident={openedIncident} onClose={() => setOpenedIncident(null)} />
    </div>
  )
}

export default App
