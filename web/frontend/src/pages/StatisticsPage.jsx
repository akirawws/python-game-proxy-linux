import { useState } from 'react'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import EmptyState from '../components/EmptyState.jsx'
import LineChart from '../components/LineChart.jsx'
import RangePicker from '../components/RangePicker.jsx'
import ServerSelect from '../components/ServerSelect.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import {
  ACTION_LABELS,
  formatBps,
  formatDateTime,
  formatNumber,
  formatPps,
  RANGE_LABELS,
  SEVERITY_LABELS,
  severityTone,
  STATUS_LABELS,
  statusTone,
} from '../utils/format.js'

const TRAFFIC_SERIES = [
  { key: 'in_pps', label: 'Входящие, pps', color: '#38bdf8', fill: true },
  { key: 'out_pps', label: 'Исходящие, pps', color: '#a78bfa' },
]

const PROTOCOL_LABELS = { tcp: 'TCP', udp: 'UDP' }

// Поле строки, по которому сгруппирована разбивка (совпадает с group_by API).
const GROUP_KEYS = {
  severity: 'severity',
  event_type: 'event_type',
  protocol: 'protocol',
  status: 'action_status',
  action: 'action',
}

function labelFor(kind, value) {
  if (value === null || value === undefined || value === '') return '—'
  if (kind === 'severity') return SEVERITY_LABELS[value] || value
  if (kind === 'protocol') return PROTOCOL_LABELS[value] || String(value).toUpperCase()
  if (kind === 'status') return STATUS_LABELS[value] || value
  if (kind === 'action') return ACTION_LABELS[value] || value
  return value
}

function toneFor(kind, value) {
  if (kind === 'severity') return severityTone(value)
  if (kind === 'status') return statusTone(value)
  return 'neutral'
}

/**
 * Таблица «значение — количество» для одной из разбивок статистики.
 * Пустые разбивки не скрываются, чтобы оператор видел, что данных нет.
 */
function Breakdown({ title, rows, kind, total }) {
  if (!rows || rows.length === 0) {
    return (
      <div className="card">
        <h2 className="card__title">{title}</h2>
        <EmptyState title="Нет данных" message="За выбранный период значения не зафиксированы." />
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card__header">
        <h2 className="card__title">{title}</h2>
        <span className="muted small">всего {formatNumber(total, 0)}</span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Значение</th>
              <th className="num">Количество</th>
              <th className="num">Доля</th>
              <th className="num">Ср. оценка</th>
              <th>Последнее</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const value = row[GROUP_KEYS[kind] || kind]
              const share = total ? (Number(row.count) / Number(total)) * 100 : 0
              return (
                <tr key={`${title}-${value}`}>
                  <td>
                    <span className={`chip chip--${toneFor(kind, value)}`}>
                      {labelFor(kind, value)}
                    </span>
                  </td>
                  <td className="num mono">{formatNumber(row.count, 0)}</td>
                  <td className="num mono">{formatNumber(share, 1)}%</td>
                  <td className="num mono">{formatNumber(row.avg_score, 2)}</td>
                  <td>{row.last_event ? formatDateTime(row.last_event) : '—'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function StatisticsPage() {
  const [range, setRange] = useState('24h')
  const [serverId, setServerId] = useState(null)

  const serversQuery = useApiData(() => api.get('/servers'), [])
  const statsQuery = useApiData(
    () => api.get('/stats', { range, server_id: serverId }),
    [range, serverId],
    { refreshMs: 30000 },
  )

  const servers = serversQuery.data?.items || []
  const payload = statsQuery.data
  const traffic = payload?.traffic || {}
  const events = payload?.events || {}
  const rules = payload?.rules || {}
  const series = traffic.series || []

  const eventBreakdowns = [
    { title: 'События по важности', rows: events.by_severity, kind: 'severity', total: events.total },
    { title: 'События по типу', rows: events.by_type, kind: 'event_type', total: events.total },
    { title: 'События по протоколу', rows: events.by_protocol, kind: 'protocol', total: events.total },
    {
      title: 'События по статусу действия',
      rows: events.by_status,
      kind: 'status',
      total: events.total,
    },
  ]

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <p className="page-head__description">
            Сводная статистика за период: нагрузка на защищаемые серверы, обнаруженные события и
            применённые правила блокировки. Значения агрегируются по интервалам выбранного периода.
          </p>
          <p className="page-head__meta">
            {payload
              ? `Источник: ${payload.source} · период: ${RANGE_LABELS[payload.range] || payload.range}`
              : 'Загрузка статистики…'}
          </p>
        </div>
        <div className="page-head__controls">
          <RangePicker value={range} onChange={setRange} />
        </div>
      </div>

      {serversQuery.error ? <Alert tone="error">{errorText(serversQuery.error)}</Alert> : null}
      {statsQuery.error ? (
        <Alert tone="error" title="Не удалось получить статистику">
          {errorText(statsQuery.error)}
        </Alert>
      ) : null}

      <div className="card">
        <div className="card__toolbar">
          <div className="inline-field">
            <span className="inline-field__label">Сервер</span>
            <ServerSelect
              servers={servers}
              value={serverId}
              onChange={setServerId}
              id="stats-server"
            />
          </div>
          <div className="toolbar-meta">
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              onClick={statsQuery.reload}
              disabled={statsQuery.loading}
            >
              Обновить
            </button>
          </div>
        </div>

        {statsQuery.loading && !payload ? (
          <LoadingBlock label="Загрузка статистики…" />
        ) : !payload ? (
          <EmptyState title="Нет данных" message="Статистика недоступна." />
        ) : (
          <>
            {payload.has_data ? null : (
              <Alert tone="info" title="Данных нет">
                {payload.message || 'За выбранный период данные не поступали.'}
              </Alert>
            )}

            <div className="stat-grid">
              <div className="stat">
                <span className="stat__label">Пиковый входящий поток</span>
                <span className="stat__value">{formatPps(traffic.peak_in_pps)}</span>
                <span className="stat__hint">средний: {formatPps(traffic.avg_in_pps)}</span>
              </div>
              <div className="stat">
                <span className="stat__label">Пиковый исходящий поток</span>
                <span className="stat__value">{formatPps(traffic.peak_out_pps)}</span>
                <span className="stat__hint">средний: {formatPps(traffic.avg_out_pps)}</span>
              </div>
              <div className="stat">
                <span className="stat__label">События за период</span>
                <span className="stat__value">{formatNumber(events.total, 0)}</span>
                <span className="stat__hint">
                  входящий трафик: {formatBps(traffic.total_in_bytes ? traffic.total_in_bytes * 8 : 0)}
                </span>
              </div>
              <div className="stat">
                <span className="stat__label">Активные правила</span>
                <span className="stat__value">{formatNumber(rules.active, 0)}</span>
                <span className="stat__hint">
                  временных: {formatNumber(rules.temporary, 0)} · за период:{' '}
                  {formatNumber(rules.created_in_period, 0)}
                </span>
              </div>
            </div>
          </>
        )}
      </div>

      {payload ? (
        <>
          <div className="card">
            <div className="card__header">
              <h2 className="card__title">Нагрузка за период</h2>
              <span className="muted small">
                точек: {formatNumber(traffic.points, 0)} · шаг {formatNumber(traffic.bucket_seconds, 0)} с
                · замеров: {formatNumber(traffic.samples, 0)}
              </span>
            </div>
            {series.length === 0 ? (
              <EmptyState
                title="Метрик нет"
                message="За выбранный период замеры трафика не поступали. Проверьте, запущен ли collector."
              />
            ) : (
              <LineChart points={series} series={TRAFFIC_SERIES} height={320} />
            )}
          </div>

          <div className="breakdown-grid">
            {eventBreakdowns.map((item) => (
              <Breakdown
                key={item.title}
                title={item.title}
                rows={item.rows}
                kind={item.kind}
                total={item.total}
              />
            ))}
          </div>

          <div className="card">
            <div className="card__header">
              <h2 className="card__title">Правила блокировки</h2>
              <span className="muted small">
                применено действий за период: {formatNumber(rules.actions_in_period, 0)}
              </span>
            </div>
            <div className="chips chips--stats">
              <span className="chip chip--static">
                Активные правила: {formatNumber(rules.active, 0)}
              </span>
              <span className="chip chip--static">
                Временные: {formatNumber(rules.temporary, 0)}
              </span>
              <span className="chip chip--static">
                Постоянные: {formatNumber(rules.permanent, 0)}
              </span>
              <span className="chip chip--static">
                Истекшие: {formatNumber(rules.expired, 0)}
              </span>
              <span className="chip chip--static">
                Создано за период: {formatNumber(rules.created_in_period, 0)}
              </span>
            </div>
            {rules.by_action?.length ? (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Действие</th>
                      <th className="num">Правил</th>
                      <th className="num">Доля</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.by_action.map((row) => (
                      <tr key={`action-${row.action}`}>
                        <td>{ACTION_LABELS[row.action] || row.action}</td>
                        <td className="num mono">{formatNumber(row.count, 0)}</td>
                        <td className="num mono">
                          {formatNumber(
                            rules.active ? (Number(row.count) / Number(rules.active)) * 100 : 0,
                            1,
                          )}
                          %
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="Правил нет"
                message="Активные правила блокировки за выбранный период отсутствуют."
              />
            )}
          </div>
        </>
      ) : null}
    </div>
  )
}
