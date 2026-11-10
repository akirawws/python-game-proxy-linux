import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'

import api from '../api/client.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { useApiData } from '../hooks/useApiData.js'

const NAV = [
  { to: '/', label: 'Дашборд', end: true },
  { to: '/servers', label: 'Серверы' },
  { to: '/traffic', label: 'Трафик' },
  { to: '/stats', label: 'Статистика' },
  { to: '/connections', label: 'Соединения' },
  { to: '/events', label: 'События' },
  { to: '/rules', label: 'Правила' },
  { to: '/settings', label: 'Настройки' },
  { to: '/security', label: 'Безопасность' },
  { to: '/audit', label: 'Аудит' },
]

const TITLES = {
  '/': 'Дашборд',
  '/servers': 'Защищаемые серверы',
  '/traffic': 'Трафик',
  '/stats': 'Статистика',
  '/connections': 'Соединения',
  '/events': 'События обнаружения',
  '/rules': 'Правила блокировки',
  '/settings': 'Настройки системы',
  '/security': 'Безопасность веб-приложения',
  '/audit': 'Журнал действий',
}

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)

  const { data: settings } = useApiData(() => api.get('/settings'), [], { refreshMs: 60000 })
  const autoMode = settings?.detection_mode === 'auto'

  useEffect(() => setSidebarOpen(false), [location.pathname])

  const handleLogout = async () => {
    setLoggingOut(true)
    try {
      await logout()
      navigate('/login', { replace: true })
    } finally {
      setLoggingOut(false)
    }
  }

  const title = TITLES[location.pathname] || 'NetShield'

  return (
    <div className="app">
      <aside className={`sidebar ${sidebarOpen ? 'is-open' : ''}`}>
        <div className="sidebar__brand">
          <span className="sidebar__logo" aria-hidden="true">
            NS
          </span>
          <div>
            <div className="sidebar__name">NetShield</div>
            <div className="sidebar__tagline">защита от DDoS</div>
          </div>
        </div>

        <nav className="sidebar__nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-link ${isActive ? 'is-active' : ''}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="sidebar__user">
            <span className="sidebar__user-login">{user?.login || '—'}</span>
            <span className="sidebar__user-role">{user?.is_admin ? 'администратор' : 'наблюдатель'}</span>
          </div>
          <button type="button" className="btn btn--ghost btn--sm" onClick={handleLogout} disabled={loggingOut}>
            {loggingOut ? 'Выход…' : 'Выйти'}
          </button>
        </div>
      </aside>

      {sidebarOpen ? (
        <button
          type="button"
          className="sidebar-backdrop"
          onClick={() => setSidebarOpen(false)}
          aria-label="Закрыть меню"
        />
      ) : null}

      <div className="main">
        <header className="topbar">
          <button
            type="button"
            className="topbar__menu"
            onClick={() => setSidebarOpen((value) => !value)}
            aria-label="Меню"
          >
            ☰
          </button>
          <h1 className="topbar__title">{title}</h1>
          <div className="topbar__right">
            <span
              className={`mode-pill ${autoMode ? 'mode-pill--auto' : 'mode-pill--observe'}`}
              title={
                autoMode
                  ? 'Автоматический режим: система применяет правила без подтверждения оператора'
                  : 'Режим наблюдения: система только предлагает правила'
              }
            >
              {autoMode ? 'Авто-режим' : 'Наблюдение'}
            </span>
          </div>
        </header>

        <main className="content">
          <Outlet />
        </main>

        <footer className="footer">
          NetShield · панель оператора · время отображается в локальной зоне
        </footer>
      </div>
    </div>
  )
}
