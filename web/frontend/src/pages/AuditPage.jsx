import { useState } from 'react'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Modal from '../components/Modal.jsx'
import Pagination from '../components/Pagination.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import { formatDateTime, RESULT_LABELS, statusTone } from '../utils/format.js'

const PAGE_SIZE = 50

const ACTION_HINTS = {
  'auth.login': 'вход в панель',
  'auth.logout': 'выход из панели',
  'server.create': 'создание сервера',
  'server.update': 'изменение сервера',
  'server.delete': 'удаление сервера',
  'server.ports': 'изменение портов',
  'rule.apply': 'создание правила',
  'rule.cancel': 'снятие правила',
  'settings.update': 'изменение настроек',
  'user.create': 'создание пользователя',
  'user.password': 'смена пароля',
}

function prettyDetails(details) {
  if (!details) return '—'
  try {
    return JSON.stringify(JSON.parse(details), null, 2)
  } catch {
    return details
  }
}

export default function AuditPage() {
  const [filters, setFilters] = useState({ action: '', result: '', hours: 168 })
  const [draftAction, setDraftAction] = useState('')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(null)

  const query = useApiData(
    () =>
      api.get('/audit', {
        action: filters.action || null,
        result: filters.result || null,
        hours: filters.hours,
        page,
        page_size: PAGE_SIZE,
      }),
    [filters, page],
    { refreshMs: 30000 },
  )

  const items = query.data?.items || []
  const total = query.data?.total || 0

  const applyAction = (event) => {
    event.preventDefault()
    setFilters((prev) => ({ ...prev, action: draftAction.trim() }))
    setPage(1)
  }

  const setFilter = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }))
    setPage(1)
  }

  if (query.loading && !query.data) return <LoadingBlock label="Загрузка журнала…" />

  return (
    <div className="stack">
      <div className="page-head">
        <p className="page-head__description">
          Журнал действий операторов и автоматических решений. Пароли, токены и cookie в журнал не
          попадают — чувствительные поля маскируются.
        </p>
      </div>

      {query.error ? <Alert tone="error">{errorText(query.error)}</Alert> : null}

      <div className="card">
        <div className="filters">
          <form className="filters__item filters__item--grow" onSubmit={applyAction}>
            <span className="filters__label">Действие</span>
            <div className="input-group">
              <input
                className="input"
                placeholder="например: auth.login"
                value={draftAction}
                onChange={(event) => setDraftAction(event.target.value)}
                maxLength={64}
                list="audit-actions"
              />
              <button type="submit" className="btn btn--ghost">
                Найти
              </button>
            </div>
            <datalist id="audit-actions">
              {Object.keys(ACTION_HINTS).map((action) => (
                <option key={action} value={action}>
                  {ACTION_HINTS[action]}
                </option>
              ))}
            </datalist>
          </form>

          <label className="filters__item filters__item--narrow">
            <span className="filters__label">Результат</span>
            <select
              className="input"
              value={filters.result}
              onChange={(event) => setFilter('result', event.target.value)}
            >
              <option value="">Любой</option>
              <option value="ok">Успешно</option>
              <option value="fail">Неудача</option>
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
              <option value={24}>24 часа</option>
              <option value={168}>7 дней</option>
              <option value={720}>30 дней</option>
              <option value={2160}>90 дней</option>
            </select>
          </label>
        </div>

        {items.length === 0 ? (
          <EmptyState
            title="Записей нет"
            message={query.data?.message || 'За выбранный период действий не зафиксировано.'}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table table--clickable">
                <thead>
                  <tr>
                    <th>Время</th>
                    <th>Пользователь</th>
                    <th>Действие</th>
                    <th>Результат</th>
                    <th>Детали</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id} onClick={() => setSelected(item)}>
                      <td className="nowrap">{formatDateTime(item.timestamp)}</td>
                      <td className="mono">{item.user_login || '—'}</td>
                      <td>
                        <div className="mono">{item.action}</div>
                        <div className="cell-subtitle">{ACTION_HINTS[item.action] || ''}</div>
                      </td>
                      <td>
                        <Badge tone={statusTone(item.result)}>
                          {RESULT_LABELS[item.result] || item.result}
                        </Badge>
                      </td>
                      <td className="cell-subtitle cell-clip">{item.details || '—'}</td>
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
        <Modal title="Запись аудита" onClose={() => setSelected(null)} wide>
          <dl className="details">
            <div>
              <dt>Время</dt>
              <dd>{formatDateTime(selected.timestamp)}</dd>
            </div>
            <div>
              <dt>Пользователь</dt>
              <dd className="mono">{selected.user_login || '—'}</dd>
            </div>
            <div>
              <dt>Действие</dt>
              <dd className="mono">{selected.action}</dd>
            </div>
            <div>
              <dt>Результат</dt>
              <dd>
                <Badge tone={statusTone(selected.result)}>
                  {RESULT_LABELS[selected.result] || selected.result}
                </Badge>
              </dd>
            </div>
          </dl>
          <h3 className="form-section__title">Детали</h3>
          <pre className="code-block">{prettyDetails(selected.details)}</pre>
        </Modal>
      ) : null}
    </div>
  )
}
