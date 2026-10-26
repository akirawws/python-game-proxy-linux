import { useState } from 'react'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Field from '../components/Field.jsx'
import Modal from '../components/Modal.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'
import { formatBps, formatNumber, PROFILE_LABELS, SERVICE_LABELS } from '../utils/format.js'

const PROFILE_OPTIONS = ['web', 'game', 'custom']
const PROTOCOL_OPTIONS = ['tcp', 'udp', 'both']
const SERVICE_OPTIONS = ['web', 'game', 'custom']

const LIMIT_FIELDS = [
  { key: 'max_pps', label: 'Пакетов в секунду', hint: 'pps' },
  { key: 'max_bps', label: 'Бит в секунду', hint: 'bit/s' },
  { key: 'max_new_tcp_per_s', label: 'Новых TCP в секунду', hint: 'conn/s' },
  { key: 'max_udp_pps', label: 'UDP-пакетов в секунду', hint: 'pps' },
  { key: 'max_new_sources', label: 'Новых источников', hint: 'ip' },
  { key: 'max_connections', label: 'Одновременных соединений', hint: 'conn' },
]

function toInt(value) {
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) ? parsed : 0
}

function emptyForm() {
  return {
    name: '',
    ip: '',
    interface: '',
    profile: 'game',
    service_type: 'game',
    internal_ip: '',
    internal_port: 0,
    description: '',
    is_active: true,
    max_pps: 5000,
    max_bps: 100000000,
    max_new_tcp_per_s: 200,
    max_udp_pps: 3000,
    max_new_sources: 100,
    max_connections: 2000,
    ports: [{ port: '', protocol: 'udp', service_type: 'game' }],
  }
}

function toForm(server) {
  return {
    name: server.name || '',
    ip: server.ip || '',
    interface: server.interface || '',
    profile: server.profile || 'custom',
    service_type: server.service_type || 'custom',
    internal_ip: server.internal_ip || '',
    internal_port: server.internal_port || 0,
    description: server.description || '',
    is_active: Boolean(server.is_active),
    max_pps: server.max_pps || 0,
    max_bps: server.max_bps || 0,
    max_new_tcp_per_s: server.max_new_tcp_per_s || 0,
    max_udp_pps: server.max_udp_pps || 0,
    max_new_sources: server.max_new_sources || 0,
    max_connections: server.max_connections || 0,
    ports: (server.ports || []).map((port) => ({
      port: String(port.port),
      protocol: port.protocol || 'tcp',
      service_type: port.service_type || 'custom',
    })),
  }
}

export default function ServersPage() {
  const serversQuery = useApiData(() => api.get('/servers'), [])
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState(emptyForm)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const [pendingDelete, setPendingDelete] = useState(null)
  const [deleting, setDeleting] = useState(false)

  const servers = serversQuery.data?.items || []
  const isNew = editing === 'new'

  const openCreate = () => {
    setForm(emptyForm())
    setError(null)
    setEditing('new')
  }

  const openEdit = (server) => {
    setForm(toForm(server))
    setError(null)
    setEditing(server)
  }

  const closeEditor = () => {
    setEditing(null)
    setError(null)
  }

  const setValue = (key) => (event) => {
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const setPort = (index, key, value) => {
    setForm((prev) => ({
      ...prev,
      ports: prev.ports.map((item, itemIndex) =>
        itemIndex === index ? { ...item, [key]: value } : item,
      ),
    }))
  }

  const addPort = () => {
    setForm((prev) => ({
      ...prev,
      ports: [...prev.ports, { port: '', protocol: 'tcp', service_type: prev.service_type }],
    }))
  }

  const removePort = (index) => {
    setForm((prev) => ({ ...prev, ports: prev.ports.filter((_, i) => i !== index) }))
  }

  const save = async (event) => {
    event.preventDefault()
    setError(null)
    setSaving(true)

    const payload = {
      name: form.name.trim(),
      ip: form.ip.trim(),
      interface: form.interface.trim(),
      profile: form.profile,
      service_type: form.service_type,
      internal_ip: form.internal_ip.trim(),
      internal_port: toInt(form.internal_port),
      description: form.description.trim(),
      is_active: Boolean(form.is_active),
      max_pps: toInt(form.max_pps),
      max_bps: toInt(form.max_bps),
      max_new_tcp_per_s: toInt(form.max_new_tcp_per_s),
      max_udp_pps: toInt(form.max_udp_pps),
      max_new_sources: toInt(form.max_new_sources),
      max_connections: toInt(form.max_connections),
      ports: form.ports
        .filter((port) => String(port.port).trim() !== '')
        .map((port) => ({
          port: toInt(port.port),
          protocol: port.protocol,
          service_type: port.service_type,
        })),
    }

    try {
      if (isNew) {
        await api.post('/servers', payload)
        setNotice('Сервер добавлен')
      } else {
        await api.patch(`/servers/${editing.id}`, payload)
        setNotice('Изменения сохранены')
      }
      closeEditor()
      await serversQuery.reload()
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  const confirmDelete = async () => {
    if (!pendingDelete) return
    setDeleting(true)
    try {
      await api.delete(`/servers/${pendingDelete.id}`)
      setNotice(`Сервер «${pendingDelete.name}» удалён`)
      setPendingDelete(null)
      await serversQuery.reload()
    } catch (err) {
      setError(err)
      setPendingDelete(null)
    } finally {
      setDeleting(false)
    }
  }

  const fieldErrors = error?.fieldErrors || {}

  if (serversQuery.loading && !serversQuery.data) return <LoadingBlock label="Загрузка серверов…" />

  return (
    <div className="stack">
      <div className="page-head">
        <p className="page-head__description">
          Список защищаемых серверов, их портов и пороговых лимитов. Значения лимитов используются
          модулем обнаружения аномалий.
        </p>
        <div className="page-head__controls">
          <button type="button" className="btn btn--primary" onClick={openCreate}>
            Добавить сервер
          </button>
        </div>
      </div>

      {notice ? (
        <Alert tone="success" onClose={() => setNotice('')}>
          {notice}
        </Alert>
      ) : null}

      {serversQuery.error ? <Alert tone="error">{errorText(serversQuery.error)}</Alert> : null}
      {error && !editing ? (
        <Alert tone="error" onClose={() => setError(null)}>
          {errorText(error)}
        </Alert>
      ) : null}

      <div className="card">
        {servers.length === 0 ? (
          <EmptyState
            title="Серверы не добавлены"
            message="Добавьте защищаемый сервер: укажите IP, интерфейс, порты и пороговые значения."
            action={
              <button type="button" className="btn btn--primary" onClick={openCreate}>
                Добавить сервер
              </button>
            }
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Сервер</th>
                  <th>IP / интерфейс</th>
                  <th>Профиль</th>
                  <th>Порты</th>
                  <th className="num">Лимиты</th>
                  <th>Состояние</th>
                  <th className="actions">Действия</th>
                </tr>
              </thead>
              <tbody>
                {servers.map((server) => (
                  <tr key={server.id}>
                    <td>
                      <div className="cell-title">{server.name}</div>
                      {server.description ? (
                        <div className="cell-subtitle">{server.description}</div>
                      ) : null}
                    </td>
                    <td>
                      <div className="mono">{server.ip}</div>
                      <div className="cell-subtitle mono">{server.interface || '—'}</div>
                    </td>
                    <td>
                      <Badge tone="info">{PROFILE_LABELS[server.profile] || server.profile}</Badge>
                      <div className="cell-subtitle">
                        {SERVICE_LABELS[server.service_type] || server.service_type}
                      </div>
                    </td>
                    <td>
                      <div className="chips">
                        {(server.ports || []).length === 0 ? (
                          <span className="muted">—</span>
                        ) : (
                          server.ports.map((port) => (
                            <span className="chip" key={`${port.port}-${port.protocol}`}>
                              {port.port}/{port.protocol}
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                    <td className="num mono small">
                      <div>{formatNumber(server.max_pps, 0)} pps</div>
                      <div>{formatBps(server.max_bps)}</div>
                    </td>
                    <td>
                      <Badge tone={server.is_active ? 'success' : 'neutral'}>
                        {server.is_active ? 'защищён' : 'отключён'}
                      </Badge>
                    </td>
                    <td className="actions">
                      <button
                        type="button"
                        className="btn btn--ghost btn--sm"
                        onClick={() => openEdit(server)}
                      >
                        Изменить
                      </button>
                      <button
                        type="button"
                        className="btn btn--danger btn--sm"
                        onClick={() => setPendingDelete(server)}
                      >
                        Удалить
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing ? (
        <Modal
          wide
          title={isNew ? 'Новый защищаемый сервер' : `Сервер «${editing.name}»`}
          onClose={closeEditor}
          footer={
            <>
              <button type="button" className="btn btn--ghost" onClick={closeEditor}>
                Отмена
              </button>
              <button type="submit" form="server-form" className="btn btn--primary" disabled={saving}>
                {saving ? 'Сохранение…' : 'Сохранить'}
              </button>
            </>
          }
        >
          {error ? (
            <Alert tone="error" title="Проверьте введённые данные">
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

          <form id="server-form" className="form-grid" onSubmit={save}>
            <Field label="Название" error={fieldErrors.name}>
              <input
                className="input"
                required
                maxLength={128}
                value={form.name}
                onChange={setValue('name')}
              />
            </Field>

            <Field label="Публичный IP" error={fieldErrors.ip} hint="IPv4 или IPv6">
              <input
                className="input mono"
                required
                value={form.ip}
                onChange={setValue('ip')}
                placeholder="203.0.113.10"
              />
            </Field>

            <Field label="Интерфейс" error={fieldErrors.interface} hint="например, eth0">
              <input
                className="input mono"
                maxLength={32}
                value={form.interface}
                onChange={setValue('interface')}
              />
            </Field>

            <Field label="Профиль защиты" error={fieldErrors.profile}>
              <select
                className="input"
                value={form.profile}
                onChange={(event) => {
                  const value = event.target.value
                  setForm((prev) => ({
                    ...prev,
                    profile: value,
                    service_type: value === 'custom' ? prev.service_type : value,
                  }))
                }}
              >
                {PROFILE_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {PROFILE_LABELS[option]}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Внутренний IP" error={fieldErrors.internal_ip} hint="адрес за прокси, необязательно">
              <input
                className="input mono"
                value={form.internal_ip}
                onChange={setValue('internal_ip')}
              />
            </Field>

            <Field label="Внутренний порт" error={fieldErrors.internal_port}>
              <input
                className="input mono"
                type="number"
                min={0}
                max={65535}
                value={form.internal_port}
                onChange={setValue('internal_port')}
              />
            </Field>

            <Field label="Описание" error={fieldErrors.description}>
              <input
                className="input"
                maxLength={512}
                value={form.description}
                onChange={setValue('description')}
              />
            </Field>

            <Field label="Состояние">
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={form.is_active}
                  onChange={setValue('is_active')}
                />
                <span>Сервер защищается</span>
              </label>
            </Field>

            <div className="form-grid__full">
              <h3 className="form-section__title">Пороговые лимиты</h3>
              <p className="muted small">
                При превышении порога детектор формирует событие. Нулевое значение означает, что
                проверка по этому параметру отключена.
              </p>
            </div>

            {LIMIT_FIELDS.map((limit) => (
              <Field key={limit.key} label={limit.label} hint={limit.hint} error={fieldErrors[limit.key]}>
                <input
                  className="input mono"
                  type="number"
                  min={0}
                  value={form[limit.key]}
                  onChange={setValue(limit.key)}
                />
              </Field>
            ))}

            <div className="form-grid__full">
              <h3 className="form-section__title">Защищаемые порты</h3>
              <p className="muted small">
                Правила могут применяться только к портам из этого списка.
              </p>
              <div className="port-editor">
                {form.ports.map((port, index) => (
                  <div className="port-row" key={index}>
                    <input
                      className="input mono"
                      type="number"
                      min={1}
                      max={65535}
                      placeholder="порт"
                      value={port.port}
                      onChange={(event) => setPort(index, 'port', event.target.value)}
                    />
                    <select
                      className="input"
                      value={port.protocol}
                      onChange={(event) => setPort(index, 'protocol', event.target.value)}
                    >
                      {PROTOCOL_OPTIONS.map((option) => (
                        <option key={option} value={option}>
                          {option.toUpperCase()}
                        </option>
                      ))}
                    </select>
                    <select
                      className="input"
                      value={port.service_type}
                      onChange={(event) => setPort(index, 'service_type', event.target.value)}
                    >
                      {SERVICE_OPTIONS.map((option) => (
                        <option key={option} value={option}>
                          {SERVICE_LABELS[option]}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className="btn btn--ghost btn--sm"
                      onClick={() => removePort(index)}
                    >
                      Удалить
                    </button>
                  </div>
                ))}
              </div>
              <button type="button" className="btn btn--ghost btn--sm" onClick={addPort}>
                Добавить порт
              </button>
            </div>
          </form>
        </Modal>
      ) : null}

      {pendingDelete ? (
        <Modal
          title="Удалить сервер?"
          onClose={() => setPendingDelete(null)}
          footer={
            <>
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => setPendingDelete(null)}
                disabled={deleting}
              >
                Отмена
              </button>
              <button
                type="button"
                className="btn btn--danger"
                onClick={confirmDelete}
                disabled={deleting}
              >
                {deleting ? 'Удаление…' : 'Удалить'}
              </button>
            </>
          }
        >
          <p>
            Сервер <strong>{pendingDelete.name}</strong> ({pendingDelete.ip}) будет удалён вместе с
            портами и связанными правилами. Действие фиксируется в журнале аудита.
          </p>
        </Modal>
      ) : null}
    </div>
  )
}
