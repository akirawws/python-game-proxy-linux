import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'

import { useAuth } from './auth/AuthContext.jsx'
import Layout from './components/Layout.jsx'
import { Spinner } from './components/Spinner.jsx'
import AuditPage from './pages/AuditPage.jsx'
import ConnectionsPage from './pages/ConnectionsPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import EventsPage from './pages/EventsPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import NotFoundPage from './pages/NotFoundPage.jsx'
import RulesPage from './pages/RulesPage.jsx'
import SecurityPage from './pages/SecurityPage.jsx'
import ServersPage from './pages/ServersPage.jsx'
import SettingsPage from './pages/SettingsPage.jsx'
import StatisticsPage from './pages/StatisticsPage.jsx'
import TrafficPage from './pages/TrafficPage.jsx'

function RequireAuth() {
  const { loading, isAuthenticated } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="boot">
        <Spinner label="Проверка сессии…" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return <Outlet />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="servers" element={<ServersPage />} />
          <Route path="traffic" element={<TrafficPage />} />
          <Route path="stats" element={<StatisticsPage />} />
          <Route path="connections" element={<ConnectionsPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  )
}
