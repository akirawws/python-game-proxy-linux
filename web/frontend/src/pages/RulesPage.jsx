import { useState } from 'react'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Field from '../components/Field.jsx'
import Modal from '../components/Modal.jsx'
import ServerSelect from '../components/ServerSelect.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import { ACTION_LABELS, formatDateTime, STATUS_LABELS, statusTone } from '../utils/format.js'

const ACTIONS = ['rate_limit', 'block_source', 'block_port', 'drop', 'alert']
const PROTOCOLS = ['tcp', 'udp', 'both']
const TTL_PRESETS = [
  { value: 300, label: '5 минут' },
  { value: 900, label: '15 минут' },
  { value: 3600, label: '1 час' },
  { value: 21600, label: '6 часов' },
  { value: 86400, label: '24 часа' },
  { value: 0, label: 'Бессрочно' },
]

const emptyRule = () => ({
  server_id: '',
  action: 'rate_limit',
  ip: '',
  port: '',
  protocol: 'tcp',
  ttl_seconds: 300,
  reason: '',
})

export default function RulesPage() {
  const [statusFilter, setStatusFilter] = useState('all')
  const [serverFilter, setServerFilter] = useState('')
  const [form, setForm] = useState(emptyRule)
  const [creating, setCreating] = useState(false)
  const [creatingBusy, setCreatingBusy] = useState(false)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [cancelling, setCancelling] = useState(null)

  const serversQuery = useApiData(() => api.get('/servers'), [])
  const rulesQuery = useApiData(
    () =>
      api.get('/rules', {
        server_id: serverFilter || null,
        status_filter: statusFilter,
      }),
    [serverFilter, statusFilter],
    { refreshMs: 30000 },
  )
  const settingsQuery = useApiData(() => api.get('/settings'), [])

  const servers = serversQuery.data?.items || []
  const rules = rulesQuery.data?.items || []
  const autoMode = settingsQuery.data?.detection_mode === 'auto'
  const selectedServer = servers.find((server) => String(server.id) === String(form.server_id))

  const setValue = (key) => (event) =>
    setForm((prev) => ({ ...prev, [key]: event.target.value }))

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    setCreatingBusy(true)
    try {
      const result = await api.post('/rules', {
        server_id: Number(form.server_id),
        action: form.action,
        ip: form.ip.trim(),
        port: form.port === '' ? 0 : Number(form.port),
        protocol: form.protocol,
        ttl_seconds: Number(form.ttl_seconds),
        reason: form.reason.trim(),
      })

      const tone = result.status === 'applied' ? 'success' : 'warning'
      setNotice({ tone, text: result.message || STATUS_LABELS[result.status] || result.status })
      setCreating(false)
      setForm(emptyRule())
      await rulesQuery.reload()
    } catch (err) {
      setError(err)
    } finally {
      setCreatingBusy(false)
    }
  }

  const cancelRule = async (rule) => {
    setCancelling(rule.id)
    setError(null)
    try {
      await api.delete(`/rules/${rule.id}`)
      setNotice({ tone: 'success', text: `Правило #${rule.id} снято` })
      await rulesQuery.reload()
    } catch (err) {
      setError(err)
    } finally {
      setCancelling(null)
    }
  }

  const fieldErrors = error?.fieldErrors || {}

  if (rulesQuery.loading && !rulesQuery.data) return <LoadingBlock label="Загрузка правил…" />

  return (
    <div className="stack">
      <div className="page-head">
        <p className="page-head__description">
          Правила ограничения и блокировки трафика. Панель не исполняет команды напрямую: правила
          передаются менеджеру firewall и применяются через nftables на защищаемом сервере.
        </p>
        <div className="page-head__controls">
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => {
              setForm(emptyRule())
              setError(null)
              setCreating(true)
            }}
            disabled={servers.length === 0}
            title={servers.length === 0 ? 'Сначала добавьте защищаемый сервер' : undefined}
          >
            Добавить правило
          </button>
        </div>
      </div>

      {autoMode ? (
        <Alert tone="warning" title="Автоматический режим">
          Система может применять решения без подтверждения оператора. Ручные правила из панели
          проходят те же проверки политики.
        </Alert>
      ) : (
        <Alert tone="info" title="Режим наблюдения">
          Автоматическое применение правил отключено. Созданные правила сохраняются в журнале и
          применяются вручную через менеджер firewall.
        </Alert>
      )}

      {notice ? (
        <Alert tone={notice.tone} onClose={() => setNotice(null)}>
          {notice.text}
        </Alert>
      ) : null}

      {error && !creating ? (
        <Alert tone="error" onClose={() => setError(null)}>
          {errorText(error)}
        </Alert>
      ) : null}
      {rulesQuery.error ? <Alert tone="error">{errorText(rulesQuery.error)}</Alert> : null}

      <div className="card">
        <div className="card__toolbar">
          <div className="inline-field">
            <span className="inline-field__label">Сервер</span>
            <ServerSelect
              servers={servers}
              value={serverFilter || null}
              onChange={(value) => setServerFilter(value ?? '')}
            />
          </div>
          <div className="inline-field">
            <span className="inline-field__label">Тип</span>
            <select
              className="input"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="all">Все активные</option>
              <option value="temporary">Временные</option>
              <option value="permanent">Постоянные</option>
              <option value="expired">Истёкшие</option>
            </select>
          </div>
          <div className="toolbar-meta">
            <span className="muted">Правил: {rules.length}</span>
            <button type="button" className="btn btn--ghost btn--sm" onClick={rulesQuery.reload}>
              Обновить
            </button>
          </div>
        </div>

        {rules.length === 0 ? (
          <EmptyState
            title="Активных правил нет"
            message="Правила создаются вручную или автоматически при обнаружении аномалии."
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Сервер</th>
                  <th>Действие</th>
                  <th>Источник</th>
                  <th>Порт</th>
                  <th>Тип</th>
                  <th>Действует до</th>
                  <th>Причина</th>
                  <th>Создано</th>
                  <th className="actions">Действия</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="mono">{rule.id}</td>
                    <td>{rule.server_name || rule.server_id}</td>
                    <td>
                      <Badge tone={rule.action === 'alert' ? 'info' : 'danger'}>
                        {ACTION_LABELS[rule.action] || rule.action}
                      </Badge>
                    </td>
                    <td className="mono">{rule.ip || '—'}</td>
                    <td className="mono">
                      {rule.port ? `${rule.port}/${rule.protocol}` : `any/${rule.protocol}`}
                    </td>
                    <td>
                      <Badge tone={rule.rule_type === 'permanent' ? 'warning' : 'neutral'}>
                        {rule.rule_type === 'permanent' ? 'постоянное' : 'временное'}
                      </Badge>
                    </td>
                    <td>{rule.expires_at ? formatDateTime(rule.expires_at) : 'бессрочно'}</td>
                    <td className="cell-subtitle">{rule.reason || '—'}</td>
                    <td>{rule.created_at ? formatDateTime(rule.created_at) : '—'}</td>
                    <td className="actions">
                      <button
                        type="button"
                        className="btn btn--danger btn--sm"
                        onClick={() => cancelRule(rule)}
                        disabled={cancelling === rule.id}
                      >
                        {cancelling === rule.id ? 'Снятие…' : 'Снять'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {creating ? (
        <Modal
          title="Новое правило"
          onClose={() => setCreating(false)}
          footer={
            <>
              <button type="button" className="btn btn--ghost" onClick={() => setCreating(false)}>
                Отмена
              </button>
              <button type="submit" form="rule-form" className="btn btn--primary" disabled={creatingBusy}>
                {creatingBusy ? 'Отправка…' : 'Создать'}
              </button>
            </>
          }
        >
          {error ? (
            <Alert tone="error" title="Правило не создано">
              <div>{errorText(error)}</div>
              {Object.keys(fieldErrors).length ? (
                <ul className="error-list">
                  {Object.entries(fieldErrors).map(([field, message]) => (
                    <li key={field}>
                      <span className="mono">{field}</span>: {message}
                    </li>
                  ))}
                </ul>
              ) : null}
            </Alert>
          ) : null}

          <form id="rule-form" className="form-grid" onSubmit={submit}>
            <Field label="Сервер" error={fieldErrors.server_id}>
              <select
                className="input"
                required
                value={form.server_id}
                onChange={setValue('server_id')}
              >
                <option value="">Выберите сервер</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>
                    {server.name} ({server.ip})
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Действие" error={fieldErrors.action}>
              <select className="input" value={form.action} onChange={setValue('action')}>
                {ACTIONS.map((action) => (
                  <option key={action} value={action}>
                    {ACTION_LABELS[action]}
                  </option>
                ))}
              </select>
            </Field>

            <Field
              label="IP-источник"
              error={fieldErrors.ip}
              hint="Оставьте пустым для правила по порту"
            >
              <input
                className="input mono"
                value={form.ip}
                onChange={setValue('ip')}
                placeholder="198.51.100.7"
              />
            </Field>

            <Field
              label="Порт"
              error={fieldErrors.port}
              hint={
                selectedServer
                  ? `Доступны порты: ${
                      (selectedServer.ports || []).map((port) => port.port).join(', ') || 'нет'
                    }. 0 — любой порт`
                  : '0 — любой порт'
              }
            >
              <input
                className="input mono"
                type="number"
                min={0}
                max={65535}
                value={form.port}
                onChange={setValue('port')}
              />
            </Field>

            <Field label="Протокол" error={fieldErrors.protocol}>
              <select className="input" value={form.protocol} onChange={setValue('protocol')}>
                {PROTOCOLS.map((protocol) => (
                  <option key={protocol} value={protocol}>
                    {protocol.toUpperCase()}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Срок действия" error={fieldErrors.ttl_seconds}>
              <select
                className="input"
                value={form.ttl_seconds}
                onChange={(event) => setForm((prev) => ({ ...prev, ttl_seconds: Number(event.target.value) }))}
              >
                {TTL_PRESETS.map((preset) => (
                  <option key={preset.value} value={preset.value}>
                    {preset.label}
                  </option>
                ))}
              </select>
            </Field>

            <div className="form-grid__full">
              <Field label="Причина" error={fieldErrors.reason} hint="Попадёт в журнал аудита">
                <input
                  className="input"
                  maxLength={256}
                  value={form.reason}
                  onChange={setValue('reason')}
                  placeholder="например: UDP-флуд на игровой порт"
                />
              </Field>
            </div>
          </form>
        </Modal>
      ) : null}
    </div>
  )
}
