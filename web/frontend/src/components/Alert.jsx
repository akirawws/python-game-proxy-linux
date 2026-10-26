const TONES = {
  info: 'alert--info',
  success: 'alert--success',
  warning: 'alert--warning',
  error: 'alert--error',
}

export default function Alert({ tone = 'info', title, children, onClose }) {
  return (
    <div className={`alert ${TONES[tone] || TONES.info}`} role={tone === 'error' ? 'alert' : 'status'}>
      <div className="alert__body">
        {title ? <div className="alert__title">{title}</div> : null}
        {children ? <div className="alert__text">{children}</div> : null}
      </div>
      {onClose ? (
        <button type="button" className="alert__close" onClick={onClose} aria-label="Закрыть">
          ×
        </button>
      ) : null}
    </div>
  )
}

export function errorText(error) {
  if (!error) return ''
  if (error.status === 401) return 'Требуется авторизация'
  if (error.status === 429) return 'Слишком много попыток. Повторите позже.'
  return error.message || 'Неизвестная ошибка'
}
