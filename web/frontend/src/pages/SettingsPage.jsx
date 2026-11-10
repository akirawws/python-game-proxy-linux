import { useEffect, useState } from 'react'

import api from '../api/client.js'
import Alert, { errorText } from '../components/Alert.jsx'
import Badge from '../components/Badge.jsx'
import Field from '../components/Field.jsx'
import { LoadingBlock } from '../components/Spinner.jsx'
import { useApiData } from '../hooks/useApiData.js'

const NUMBER_FIELDS = [
  {
    key: 'collection_interval_sec',
    label: 'Интервал сбора, секунд',
    hint: 'как часто collector снимает метрики (1–60)',
    min: 1,
    max: 60,
  },
  {
    key: 'confirmation_intervals',
    label: 'Интервалов подтверждения',
    hint: 'сколько подряд замеров должны превысить порог (1–10)',
    min: 1,
    max: 10,
  },
  {
    key: 'cooldown_seconds',
    label: 'Cooldown, секунд',
    hint: 'пауза перед повторным правилом для того же источника',
    min: 0,
    max: 86400,
  },
  {
    key: 'max_concurrent_blocks',
    label: 'Максимум одновременных блокировок',
    hint: 'ограничение количества активных правил',
    min: 0,
    max: 1000,
  },
  {
    key: 'metrics_retention_days',
    label: 'Хранение метрик, дней',
    hint: 'срок жизни сырых метрик в хранилище',
    min: 1,
    max: 365,
  },
  {
    key: 'event_retention_days',
    label: 'Хранение событий, дней',
    hint: 'срок жизни записей об аномалиях',
    min: 1,
    max: 365,
  },
]

export default function SettingsPage() {
  const query = useApiData(() => api.get('/settings'), [])
  const [form, setForm] = useState(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState('')

  useEffect(() => {
    if (query.data) setForm(query.data)
  }, [query.data])

  useEffect(() => {
    if (query.error) setError(query.error)
  }, [query.error])

  if (!form) {
    if (query.error) return <Alert tone="error">{errorText(query.error)}</Alert>
    return <LoadingBlock label="Загрузка настроек…" />
  }

  const setValue = (key) => (event) => {
    const value =
      event.target.type === 'checkbox' ? event.target.checked : event.target.value
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const save = async (event) => {
    event.preventDefault()
    setError(null)
    setNotice('')

    if (
      form.detection_mode === 'auto' &&
      !window.confirm(
        'Автоматический режим: система будет применять правила блокировки без подтверждения оператора. Продолжить?',
      )
    ) {
      return
    }

    setSaving(true)
    try {
      const payload = {
        detection_mode: form.detection_mode,
        auto_actions_enabled: Boolean(form.auto_actions_enabled),
        collection_interval_sec: Number(form.collection_interval_sec),
        confirmation_intervals: Number(form.confirmation_intervals),
        cooldown_seconds: Number(form.cooldown_seconds),
        max_concurrent_blocks: Number(form.max_concurrent_blocks),
        metrics_retention_days: Number(form.metrics_retention_days),
        event_retention_days: Number(form.event_retention_days),
      }
      const saved = await api.put('/settings', payload)
      setForm(saved)
      setNotice('Настройки сохранены. Изменение зафиксировано в журнале аудита.')
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  const autoMode = form.detection_mode === 'auto'
  const fieldErrors = error?.fieldErrors || {}

  return (
    <div className="stack">
      <div className="page-head">
        <p className="page-head__description">
          Параметры обнаружения и применения правил. Настройки общие для всей системы и влияют на
          работу collector, detector и firewall.
        </p>
      </div>

      {notice ? (
        <Alert tone="success" onClose={() => setNotice('')}>
          {notice}
        </Alert>
      ) : null}

      {error ? (
        <Alert tone="error" title="Не удалось сохранить настройки">
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

      <form className="stack" onSubmit={save}>
        <div className="card">
          <h2 className="card__title">Режим работы</h2>
          <p className="muted small">
            В режиме наблюдения система только фиксирует события и предлагает правила. В
            автоматическом режиме правила применяются без участия оператора.
          </p>

          <div className="mode-options">
            <button
              type="button"
              className={`mode-option ${!autoMode ? 'is-active' : ''}`}
              onClick={() => setForm((prev) => ({ ...prev, detection_mode: 'observation' }))}
              aria-pressed={!autoMode}
            >
              <span className="mode-option__title">Наблюдение</span>
              <span className="mode-option__text">
                Решения только предлагаются, блокировки не применяются автоматически.
              </span>
              <Badge tone="info">безопасный режим</Badge>
            </button>

            <button
              type="button"
              className={`mode-option mode-option--danger ${autoMode ? 'is-active' : ''}`}
              onClick={() =>
                setForm((prev) => ({ ...prev, detection_mode: 'auto', auto_actions_enabled: true }))
              }
              aria-pressed={autoMode}
            >
              <span className="mode-option__title">Автоматический</span>
              <span className="mode-option__text">
                Правила применяются сразу после подтверждения аномалии детектором.
              </span>
              <Badge tone="danger">боевой режим</Badge>
            </button>
          </div>

          <label className="checkbox checkbox--standalone">
            <input
              type="checkbox"
              checked={Boolean(form.auto_actions_enabled)}
              onChange={setValue('auto_actions_enabled')}
              disabled={autoMode}
            />
            <span>
              Разрешить автоматические действия
              <span className="muted small">
                {' '}
                — при автоматическом режиме включается принудительно
              </span>
            </span>
          </label>

          {autoMode ? (
            <Alert tone="warning" title="Внимание: боевой режим">
              Убедитесь, что пороги и лимиты настроены корректно, а на серверах доступен менеджер
              firewall. Ошибочное правило может заблокировать легитимный трафик.
            </Alert>
          ) : null}
        </div>

        <div className="card">
          <h2 className="card__title">Обнаружение и хранение</h2>
          <div className="form-grid">
            {NUMBER_FIELDS.map((field) => (
              <Field
                key={field.key}
                label={field.label}
                hint={field.hint}
                error={fieldErrors[field.key]}
              >
                <input
                  className="input mono"
                  type="number"
                  min={field.min}
                  max={field.max}
                  value={form[field.key]}
                  onChange={setValue(field.key)}
                />
              </Field>
            ))}
          </div>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn--primary" disabled={saving}>
            {saving ? 'Сохранение…' : 'Сохранить настройки'}
          </button>
          <button
            type="button"
            className="btn btn--ghost"
            onClick={() => query.data && setForm(query.data)}
            disabled={saving}
          >
            Сбросить изменения
          </button>
        </div>
      </form>
    </div>
  )
}
