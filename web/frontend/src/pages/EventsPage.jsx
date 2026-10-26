import { useState } from 'react'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Modal from '../components/Modal.jsx'
import Pagination from '../components/Pagination.jsx'
import ServerSelect from '../components/ServerSelect.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import {
  formatDateTime,
  formatNumber,
  formatRelative,
  SEVERITY_LABELS,
  severityTone,
  STATUS_LABELS,
  statusTone,
} from '../utils/format.js'

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const PAGE_SIZE = 25

function prettyDetails(details) {
  if (!details) return '—'
  try {
    return JSON.stringify(JSON.parse(details), null, 2)
  } catch {
    return details
  }
}

export default function EventsPage() {
  const [filters, setFilters] = useState({
    serverId: '',
    severity: '',
    protocol: '',
    actionStatus: '',
    hours: 24,
  })
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(null)

  const serversQuery = useApiData(() => api.get('/servers'), [])
  const eventsQuery = useApiData(
    () =>
      api.get('/events', {
        server_id: filters.serverId || null,
        severity: filters.severity || null,
        protocol: filters.protocol || null,
        action_status: filters.actionStatus || null,
        hours: filters.hours,
        page,
        page_size: PAGE_SIZE,
      }),
    [filters, page],
    { refreshMs: 20000 },
  )

  const statsQuery = useApiData(
    () =>
      api.get('/events/stats', {
        server_id: filters.serverId || null,
        hours: filters.hours,
      }),
    [filters.serverId, filters.hours],
    { refreshMs: 30000 },
  )

  const servers = serversQuery.data?.items || []
  const events = eventsQuery.data?.items || []
  const total = eventsQuery.data?.total || 0
  const stats = statsQuery.data?.items || []
  const statsTotal = statsQuery.data?.total || 0

  const setFilter = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }))
    setPage(1)
  }

  if (eventsQuery.loading && !eventsQuery.data) return <LoadingBlock label="Загрузка событий…" />

  return (
    <div className="stack">
      <div className="page-head">
        <p className="page-head__description">
          События, сформированные модулем обнаружения аномалий. Фильтры применяются на стороне
          сервера, список обновляется автоматически.
        </p>
      </div>

      {eventsQuery.error ? <Alert tone="error">{errorText(eventsQuery.error)}</Alert> : null}

      <div className="card">
        <div className="filters">
          <label className="filters__item">
            <span className="filters__label">Сервер</span>
            <ServerSelect
              servers={servers}
              value={filters.serverId || null}
              onChange={(value) => setFilter('serverId', value ?? '')}
            />
          </label>

          <label className="filters__item">
            <span className="filters__label">Важность</span>
            <select
              className="input"
              value={filters.severity}
              onChange={(event) => setFilter('severity', event.target.value)}
            >
              <option value="">Любая</option>
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {SEVERITY_LABELS[severity]}
                </option>
              ))}
            </select>
          </label>

          <label className="filters__item">
            <span className="filters__label">Протокол</span>
            <select
              className="input"
              value={filters.protocol}
              onChange={(event) => setFilter('protocol', event.target.value)}
            >
              <option value="">Любой</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>

          <label className="filters__item">
            <span className="filters__label">Статус действия</span>
            <select
              className="input"
              value={filters.actionStatus}
              onChange={(event) => setFilter('actionStatus', event.target.value)}
            >
              <option value="">Любой</option>
              <option value="proposed">Предложено</option>
              <option value="pending">Ожидает</option>
              <option value="applied">Применено</option>
              <option value="rejected">Отклонено</option>
            </select>
          </label>

          <label className="filters__item filters__item--narrow">
            <span className="filters__label">Период</span>
            <select
              className="input"
              value={filters.hours}
              onChange={(event) => setFilter('hours', Number(event.target.value))}
            >
              <option value={1}>1 час</option>
              <option value={6}>6 часов</option>
              <option value={24}>24 часа</option>
              <option value={72}>3 дня</option>
              <option value={168}>7 дней</option>
            </select>
          </label>
        </div>

        <div className="chips chips--stats">
          <span className="chip chip--static">Всего за период: {statsTotal}</span>
          {stats.map((row) => (
            <span className={`chip chip--${severityTone(row.severity)}`} key={row.severity}>
              {SEVERITY_LABELS[row.severity] || row.severity}: {formatNumber(row.count, 0)}
            </span>
          ))}
        </div>

        {events.length === 0 ? (
          <EmptyState
            title="Событий нет"
            message={
              eventsQuery.data?.message ||
              'За выбранный период аномалий не зафиксировано. Это нормальное состояние.'
            }
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table table--clickable">
                <thead>
                  <tr>
                    <th>Время</th>
                    <th>Сервер</th>
                    <th>Тип события</th>
                    <th>Протокол</th>
                    <th>Важность</th>
                    <th className="num">Оценка</th>
                    <th>Действие</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={event.id} onClick={() => setSelected(event)}>
                      <td>
                        <div>{formatDateTime(event.timestamp)}</div>
                        <div className="cell-subtitle">{formatRelative(event.timestamp)}</div>
                      </td>
                      <td>{event.server_name || event.server_id}</td>
                      <td className="mono">{event.event_type}</td>
                      <td className="mono">{(event.protocol || '—').toUpperCase()}</td>
                      <td>
                        <Badge tone={severityTone(event.severity)}>
                          {SEVERITY_LABELS[event.severity] || event.severity}
                        </Badge>
                      </td>
                      <td className="num mono">{formatNumber(event.score, 2)}</td>
                      <td>
                        <Badge tone={statusTone(event.action_status)}>
                          {STATUS_LABELS[event.action_status] || event.action_status}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onChange={setPage} />
          </>
        )}
      </div>

      {selected ? (
        <Modal title="Детали события" onClose={() => setSelected(null)} wide>
          <dl className="details">
            <div>
              <dt>Время</dt>
              <dd>{formatDateTime(selected.timestamp)}</dd>
            </div>
            <div>
              <dt>Сервер</dt>
              <dd>{selected.server_name || selected.server_id}</dd>
            </div>
            <div>
              <dt>Тип</dt>
              <dd className="mono">{selected.event_type}</dd>
            </div>
            <div>
              <dt>Протокол</dt>
              <dd className="mono">{(selected.protocol || '—').toUpperCase()}</dd>
            </div>
            <div>
              <dt>Важность</dt>
              <dd>
                <Badge tone={severityTone(selected.severity)}>
                  {SEVERITY_LABELS[selected.severity] || selected.severity}
                </Badge>
              </dd>
            </div>
            <div>
              <dt>Оценка</dt>
              <dd className="mono">{formatNumber(selected.score, 3)}</dd>
            </div>
            <div>
              <dt>Статус действия</dt>
              <dd>
                <Badge tone={statusTone(selected.action_status)}>
                  {STATUS_LABELS[selected.action_status] || selected.action_status}
                </Badge>
              </dd>
            </div>
          </dl>
          <h3 className="form-section__title">Технические детали</h3>
          <pre className="code-block">{prettyDetails(selected.details)}</pre>
        </Modal>
      ) : null}
    </div>
  )
}
