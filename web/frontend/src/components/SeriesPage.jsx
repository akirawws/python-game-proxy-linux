import { useState } from 'react'

import api from '../api/client.js'
import { useApiData } from '../hooks/useApiData.js'
import { formatNumber, RANGE_LABELS } from '../utils/format.js'
import Alert, { errorText } from './Alert.jsx'
import EmptyState from './EmptyState.jsx'
import LineChart from './LineChart.jsx'
import RangePicker from './RangePicker.jsx'
import ServerSelect from './ServerSelect.jsx'
import { LoadingBlock } from './Spinner.jsx'

/**
 * Общая страница графика метрик (трафик / соединения).
 */
export default function SeriesPage({ endpoint, series, metrics, description, refreshMs = 15000 }) {
  const [range, setRange] = useState('1h')
  const [serverId, setServerId] = useState(null)

  const serversQuery = useApiData(() => api.get('/servers'), [])
  const seriesQuery = useApiData(
    () => api.get(endpoint, { range, server_id: serverId }),
    [endpoint, range, serverId],
    { refreshMs },
  )

  const servers = serversQuery.data?.items || []
  const payload = seriesQuery.data
  const points = payload?.points || []
  const lastPoint = points.length ? points[points.length - 1] : null

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <p className="page-head__description">{description}</p>
        </div>
        <div className="page-head__controls">
          <RangePicker value={range} onChange={setRange} />
        </div>
      </div>

      {serversQuery.error ? <Alert tone="error">{errorText(serversQuery.error)}</Alert> : null}

      <div className="card">
        <div className="card__toolbar">
          <div className="inline-field">
            <span className="inline-field__label">Сервер</span>
            <ServerSelect
              servers={servers}
              value={serverId}
              onChange={setServerId}
              id="series-server"
            />
          </div>
          <div className="toolbar-meta">
            {payload ? (
              <>
                <span className="muted">Источник: {payload.source}</span>
                <span className="muted">Период: {RANGE_LABELS[payload.range] || payload.range}</span>
                <span className="muted">
                  Точек: {payload.points?.length || 0} · шаг {payload.bucket_seconds} с
                </span>
              </>
            ) : null}
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              onClick={seriesQuery.reload}
              disabled={seriesQuery.loading}
            >
              Обновить
            </button>
          </div>
        </div>

        {seriesQuery.error ? (
          <Alert tone="error" title="Не удалось получить метрики">
            {errorText(seriesQuery.error)}
          </Alert>
        ) : null}

        {seriesQuery.loading && !payload ? (
          <LoadingBlock />
        ) : !payload || payload.has_data === false || points.length === 0 ? (
          <EmptyState
            title="Нет данных"
            message={payload?.message || 'Метрики за выбранный период не поступали. Проверьте, запущен ли collector.'}
          />
        ) : (
          <>
            {payload.stale ? (
              <Alert tone="warning" title="Данные устарели">
                {payload.message || 'Последняя точка метрик получена слишком давно.'}
              </Alert>
            ) : null}

            <LineChart points={points} series={series} height={340} />
          </>
        )}
      </div>

      {lastPoint ? (
        <div className="stat-grid">
          {metrics.map((metric) => (
            <div className="stat" key={metric.key}>
              <span className="stat__label">{metric.label}</span>
              <span className="stat__value">
                {metric.format ? metric.format(lastPoint[metric.key]) : formatNumber(lastPoint[metric.key])}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}
