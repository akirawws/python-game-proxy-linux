export default function Pagination({ page, pageSize, total, onChange }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  if (total <= pageSize) {
    return (
      <div className="pagination">
        <span className="pagination__info">Всего: {total}</span>
      </div>
    )
  }
  return (
    <div className="pagination">
      <button
        type="button"
        className="btn btn--ghost btn--sm"
        onClick={() => onChange(page - 1)}
        disabled={page <= 1}
      >
        Назад
      </button>
      <span className="pagination__info">
        Страница {page} из {pages} · всего {total}
      </span>
      <button
        type="button"
        className="btn btn--ghost btn--sm"
        onClick={() => onChange(page + 1)}
        disabled={page >= pages}
      >
        Вперёд
      </button>
    </div>
  )
}
