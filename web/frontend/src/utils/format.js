const numberFormatter = new Intl.NumberFormat('ru-RU', {
  maximumFractionDigits: 2,
})

const compactFormatter = new Intl.NumberFormat('ru-RU', {
  notation: 'compact',
  maximumFractionDigits: 1,
})

export function formatNumber(value, digits = 2) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—'
  const number = Number(value)
  if (digits === 2) return numberFormatter.format(number)
  return new Intl.NumberFormat('ru-RU', { maximumFractionDigits: digits }).format(number)
}

export function formatCompact(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—'
  return compactFormatter.format(Number(value))
}

/** Бит/с в человекочитаемый вид. */
export function formatBps(bps) {
  if (bps === null || bps === undefined) return '—'
  const value = Number(bps)
  if (!Number.isFinite(value)) return '—'
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с']
  let scaled = value
  let index = 0
  while (Math.abs(scaled) >= 1000 && index < units.length - 1) {
    scaled /= 1000
    index += 1
  }
  return `${formatNumber(scaled, 1)} ${units[index]}`
}

export function formatPps(pps) {
  if (pps === null || pps === undefined) return '—'
  return `${formatCompact(pps)} pps`
}

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—'
  const value = Math.max(0, Math.round(Number(seconds)))
  if (value === 0) return 'бессрочно'
  const days = Math.floor(value / 86400)
  const hours = Math.floor((value % 86400) / 3600)
  const minutes = Math.floor((value % 3600) / 60)
  if (days) return `${days} д ${hours} ч`
  if (hours) return `${hours} ч ${minutes} мин`
  if (minutes) return `${minutes} мин`
  return `${value} с`
}

/** Бэкенд отдаёт ISO-время в UTC — показываем в локальной зоне. */
export function formatDateTime(value) {
  if (!value) return '—'
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatTime(value) {
  if (!value) return '—'
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleTimeString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatRelative(value) {
  if (!value) return '—'
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  const diff = Math.round((Date.now() - date.getTime()) / 1000)
  if (diff < 5) return 'только что'
  if (diff < 60) return `${diff} с назад`
  if (diff < 3600) return `${Math.floor(diff / 60)} мин назад`
  if (diff < 86400) return `${Math.floor(diff / 3600)} ч назад`
  return `${Math.floor(diff / 86400)} дн назад`
}

export const SEVERITY_LABELS = {
  info: 'Инфо',
  low: 'Низкая',
  medium: 'Средняя',
  high: 'Высокая',
  critical: 'Критическая',
}

export const ACTION_LABELS = {
  rate_limit: 'Ограничение скорости',
  block_source: 'Блокировка источника',
  block_port: 'Блокировка порта',
  drop: 'Сброс трафика',
  alert: 'Только оповещение',
}

export const STATUS_LABELS = {
  ok: 'Успешно',
  fail: 'Неудача',
  pending: 'Ожидает применения',
  applied: 'Применено',
  proposed: 'Предложено',
  cancelled: 'Снято',
  rejected: 'Отклонено',
  error: 'Ошибка',
  warn: 'Внимание',
  degraded: 'Деградация',
}

export const PROFILE_LABELS = {
  web: 'Веб-сервер',
  game: 'Игровой сервер',
  custom: 'Свой профиль',
}

export const SERVICE_LABELS = {
  web: 'Веб',
  game: 'Игра',
  custom: 'Другое',
}

export const RANGE_LABELS = {
  '5m': '5 минут',
  '1h': '1 час',
  '24h': '24 часа',
  '7d': '7 дней',
}

export const RESULT_LABELS = {
  ok: 'Успешно',
  fail: 'Неудача',
}

export function severityTone(severity) {
  return {
    info: 'neutral',
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'critical',
  }[severity] || 'neutral'
}

export function statusTone(status) {
  return {
    ok: 'success',
    applied: 'success',
    pending: 'warning',
    proposed: 'info',
    cancelled: 'neutral',
    rejected: 'danger',
    fail: 'danger',
    error: 'danger',
    warn: 'warning',
    degraded: 'warning',
  }[status] || 'neutral'
}
