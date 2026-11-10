import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import { formatDateTime, STATUS_LABELS, statusTone } from '../utils/format.js'

const RECOMMENDATIONS = [
  'Задайте NETSHIELD_SECRET_KEY в .env — без него ключ подписи сессий генерируется заново при каждом запуске.',
  'Включайте COOKIE_SECURE=true только после настройки HTTPS, иначе браузер не отправит cookie.',
  'CSRF-защита должна оставаться включённой: заголовок X-CSRF-Token обязателен для всех изменяющих запросов.',
  'Публикуйте панель через nginx с TLS и ограничением доступа по IP или VPN.',
  'Проверяйте журнал аудита: все попытки входа, изменения серверов и правил фиксируются.',
]

export default function SecurityPage() {
  const query = useApiData(() => api.get('/security/status'), [], { refreshMs: 60000 })

  if (query.loading && !query.data) return <LoadingBlock label="Проверка конфигурации…" />
  if (query.error) return <Alert tone="error">{errorText(query.error)}</Alert>

  const checks = query.data?.checks || []
  const components = query.data?.components || []
  const problems = checks.filter((check) => check.status !== 'ok')

  return (
    <div className="stack">
      <div className="page-head">
        <p className="page-head__description">
          Проверка конфигурации веб-приложения и состояния подсистем. Отчёт обновляется
          автоматически и не изменяет настройки.
        </p>
        <div className="page-head__controls">
          <button type="button" className="btn btn--ghost" onClick={query.reload}>
            Проверить снова
          </button>
        </div>
      </div>

      {problems.length === 0 ? (
        <Alert tone="success" title="Замечаний не найдено">
          Все проверенные параметры соответствуют безопасной конфигурации.
        </Alert>
      ) : (
        <Alert tone="warning" title={`Требуют внимания: ${problems.length}`}>
          Ниже перечислены параметры, которые стоит исправить перед промышленной эксплуатацией.
        </Alert>
      )}

      <div className="card">
        <h2 className="card__title">Проверки конфигурации</h2>
        <div className="check-list">
          {checks.map((check) => (
            <div className="check" key={check.name}>
              <div className="check__head">
                <span className="check__name">{check.name}</span>
                <Badge tone={statusTone(check.status)}>
                  {STATUS_LABELS[check.status] || check.status}
                </Badge>
              </div>
              <p className="check__message">{check.message}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="card__title">Состояние подсистем</h2>
        {components.length === 0 ? (
          <EmptyState
            title="Нет записей о состоянии"
            message="Компоненты ещё не публиковали статус. Записи появляются после первого запуска collector и detector."
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Компонент</th>
                  <th>Статус</th>
                  <th>Сообщение</th>
                  <th>Обновлено</th>
                </tr>
              </thead>
              <tbody>
                {components.map((component) => (
                  <tr key={component.id ?? component.component}>
                    <td className="mono">{component.component}</td>
                    <td>
                      <Badge tone={statusTone(component.status)}>
                        {STATUS_LABELS[component.status] || component.status}
                      </Badge>
                    </td>
                    <td>{component.message || '—'}</td>
                    <td>{component.updated_at ? formatDateTime(component.updated_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="card__title">Рекомендации по безопасной эксплуатации</h2>
        <ul className="recommendations">
          {RECOMMENDATIONS.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}
