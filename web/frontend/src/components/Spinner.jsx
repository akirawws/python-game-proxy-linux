export function Spinner({ label = 'Загрузка…' }) {
  return (
    <div className="spinner" role="status">
      <span className="spinner__ring" aria-hidden="true" />
      <span>{label}</span>
    </div>
  )
}

export function LoadingBlock({ label = 'Загрузка данных…' }) {
  return (
    <div className="loading-block">
      <Spinner label={label} />
    </div>
  )
}
