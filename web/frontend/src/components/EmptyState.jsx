export default function EmptyState({ title = 'Нет данных', message, action }) {
  return (
    <div className="empty">
      <div className="empty__icon" aria-hidden="true">
        ∅
      </div>
      <div className="empty__title">{title}</div>
      {message ? <p className="empty__message">{message}</p> : null}
      {action ? <div className="empty__action">{action}</div> : null}
    </div>
  )
}
