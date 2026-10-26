import { Link } from 'react-router-dom'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import {
  formatBps,
  formatDateTime,
  formatNumber,
  formatPps,
  formatRelative,
  PROFILE_LABELS,
  statusTone,
} from '../utils/format.js'

export default function DashboardPage() {
  const { data, error, loading, updatedAt, reload } = useApiData(
    () => api.get('/metrics/overview'),
    [],
    { refreshMs: 10000 },
  )

  if (loading && !data) return <LoadingBlock label="Загрузка состояния системы…" />

  if (error) {
    return (
      <Alert tone="error" title="Не удалось загрузить дашборд">
        {errorText(error)}
      </Alert>
    )
  }

  const gateway = data?.gateway || {}
  const totals = data?.totals || {}
  const items = data?.items || []
  const autoMode = gateway.detection_mode === 'auto'

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <p className="page-head__description">
            Сводка по защищаемым серверам. Данные обновляются автоматически каждые 10 секунд.
          </p>
          <p className="page-head__meta">
            Обновлено: {updatedAt ? formatDateTime(updatedAt) : '—'}
            {' · '}
            <span className="muted">источник метрик: {gateway.metrics_source || '—'}</span>
          </p>
        </div>
        <div className="page-head__controls">
          <button type="button" className="btn btn--ghost" onClick={reload}>
            Обновить
          </button>
        </div>
      </div>

      {autoMode ? (
        <Alert tone="warning" title="Автоматический режим включён">
          Система применяет решения без подтверждения оператора. Проверьте настройки порогов и
          лимитов перед работой на реальном трафике.
        </Alert>
      ) : (
        <Alert tone="info" title="Режим наблюдения">
          Система только фиксирует события и предлагает правила. Автоматическая блокировка
          отключена — правила применяются вручную.
        </Alert>
      )}

      <div className="stat-grid">
        <div className="stat">
          <span className="stat__label">Серверов под защитой</span>
          <span className="stat__value">
            {gateway.servers_active ?? 0}
            <span className="stat__suffix"> / {gateway.servers_total ?? 0}</span>
          </span>
        </div>
        <div className="stat">
          <span className="stat__label">Входящий поток</span>
          <span className="stat__value">{formatPps(totals.in_pps || 0)}</span>
          <span className="stat__hint">{formatBps(totals.in_bps || 0)}</span>
        </div>
        <div className="stat">
          <span className="stat__label">События за 24 часа</span>
          <span className="stat__value">{formatNumber(totals.events_24h || 0, 0)}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Источник метрик</span>
          <span className="stat__value stat__value--small">
            {gateway.metrics_source === 'clickhouse' ? 'ClickHouse' : 'SQLite'}
          </span>
          <span className="stat__hint">
            {gateway.metrics_source === 'clickhouse'
              ? 'боевое хранилище метрик'
              : 'локальное хранилище (fallback)'}
          </span>
        </div>
      </div>

      <div className="card">
        <div className="card__header">
          <h2 className="card__title">Серверы</h2>
          <Link className="btn btn--ghost btn--sm" to="/servers">
            Управление серверами
          </Link>
        </div>

        {items.length === 0 ? (
          <EmptyState
            title="Серверы не добавлены"
            message="Добавьте первый защищаемый сервер, чтобы видеть метрики и события."
            action={
              <Link className="btn btn--primary" to="/servers">
                Добавить сервер
              </Link>
            }
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Сервер</th>
                  <th>IP</th>
                  <th>Профиль</th>
                  <th className="num">Вх. pps</th>
                  <th className="num">Исх. pps</th>
                  <th className="num">Трафик</th>
                  <th className="num">Conntrack</th>
                  <th>Данные</th>
                  <th>Обновлено</th>
                </tr>
              </thead>
              <tbody>
                {items.map((server) => (
                  <tr key={server.server_id}>
                    <td>
                      <Link to="/traffic">{server.name}</Link>
                      {!server.is_active ? (
                        <Badge tone="neutral" title="Сервер отключён">
                          выкл
                        </Badge>
                      ) : null}
                    </td>
                    <td className="mono">{server.ip}</td>
                    <td>{PROFILE_LABELS[server.profile] || server.profile}</td>
                    <td className="num mono">{formatNumber(server.in_pps, 1)}</td>
                    <td className="num mono">{formatNumber(server.out_pps, 1)}</td>
                    <td className="num mono">{formatBps(server.in_bps)}</td>
                    <td className="num mono">{formatNumber(server.conntrack_count, 0)}</td>
                    <td>
                      <Badge tone={server.has_data ? 'success' : 'warning'}>
                        {server.has_data ? 'актуальны' : 'нет данных'}
                      </Badge>
                    </td>
                    <td title={server.message || ''}>
                      {server.last_sample ? formatRelative(server.last_sample) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="card__title">Состояние компонентов</h2>
        <div className="component-grid">
          <div className="component">
            <span className="component__name">Режим обнаружения</span>
            <Badge tone={autoMode ? 'danger' : 'info'}>
              {autoMode ? 'автоматический' : 'наблюдение'}
            </Badge>
          </div>
          <div className="component">
            <span className="component__name">Автодействия</span>
            <Badge tone={gateway.auto_actions_enabled ? 'danger' : 'success'}>
              {gateway.auto_actions_enabled ? 'включены' : 'выключены'}
            </Badge>
          </div>
          <div className="component">
            <span className="component__name">Хранилище метрик</span>
            <Badge tone={gateway.metrics_source === 'clickhouse' ? 'success' : 'warning'}>
              {gateway.metrics_source === 'clickhouse' ? 'ClickHouse' : 'SQLite'}
            </Badge>
          </div>
          <div className="component">
            <span className="component__name">Защита</span>
            <Badge tone={statusTone(gateway.servers_active > 0 ? 'ok' : 'warn')}>
              {gateway.servers_active > 0 ? 'активна' : 'нет активных серверов'}
            </Badge>
          </div>
        </div>
        <p className="muted small">
          Подробную проверку конфигурации безопасности смотрите в разделе «Безопасность».
        </p>
      </div>
    </div>
  )
}
