import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext.jsx'

export default function LoginPage() {
  const { login, isAuthenticated, loading } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from && location.state.from !== '/login' ? location.state.from : '/'

  const [form, setForm] = useState({ login: '', password: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (!loading && isAuthenticated) {
    return <Navigate to={from} replace />
  }

  const update = (field) => (event) => setForm((prev) => ({ ...prev, [field]: event.target.value }))

  const onSubmit = async (event) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(form.login.trim(), form.password)
      navigate(from, { replace: true })
    } catch (err) {
      if (err.status === 401) setError('Неверный логин или пароль')
      else if (err.status === 429) setError('Слишком много попыток входа. Попробуйте позже.')
      else if (err.status === 403) setError('Сессия устарела, обновите страницу и повторите вход.')
      else setError(err.message || 'Не удалось войти')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <div className="login__aside">
        <div className="login__brand">
          <span className="login__logo" aria-hidden="true">
            NS
          </span>
          <div>
            <div className="login__brand-name">NetShield</div>
            <div className="login__brand-tagline">система защиты от DDoS-атак</div>
          </div>
        </div>
        <ul className="login__features">
          <li>Сбор и визуализация метрик трафика в реальном времени</li>
          <li>Обнаружение аномалий по порогам и поведенческим моделям</li>
          <li>Управление правилами блокировки на защищаемых серверах</li>
          <li>Полный журнал действий операторов и проверки безопасности</li>
        </ul>
        <p className="login__note">
          Доступ выдаётся администратором. Учётная запись по умолчанию создаётся командой
          <code> python -m app.cli create-admin</code>.
        </p>
      </div>

      <div className="login__panel">
        <form className="login__form" onSubmit={onSubmit}>
          <h1 className="login__title">Вход в панель</h1>
          <p className="login__subtitle">Введите учётные данные администратора</p>

          {error ? (
            <div className="alert alert--error" role="alert">
              <div className="alert__body">
                <div className="alert__text">{error}</div>
              </div>
            </div>
          ) : null}

          <label className="field" htmlFor="login-input">
            <span className="field__label">Логин</span>
            <input
              id="login-input"
              className="input"
              type="text"
              autoComplete="username"
              autoFocus
              required
              maxLength={64}
              value={form.login}
              onChange={update('login')}
            />
          </label>

          <label className="field" htmlFor="password-input">
            <span className="field__label">Пароль</span>
            <input
              id="password-input"
              className="input"
              type="password"
              autoComplete="current-password"
              required
              maxLength={256}
              value={form.password}
              onChange={update('password')}
            />
          </label>

          <button type="submit" className="btn btn--primary btn--block" disabled={busy}>
            {busy ? 'Проверка…' : 'Войти'}
          </button>

          <p className="login__hint">
            Все попытки входа фиксируются в журнале аудита. После нескольких неудач вход временно
            блокируется.
          </p>
        </form>
      </div>
    </div>
  )
}
