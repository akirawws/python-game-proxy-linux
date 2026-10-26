import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <div className="card">
      <h2>Страница не найдена</h2>
      <p className="muted">Такого раздела в панели нет.</p>
      <Link className="btn btn--primary" to="/">
        Вернуться на дашборд
      </Link>
    </div>
  )
}
