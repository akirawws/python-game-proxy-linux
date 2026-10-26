import SeriesPage from '../components/SeriesPage.jsx'
import { formatNumber } from '../utils/format.js'

const SERIES = [
  { key: 'tcp_new', label: 'Новые TCP-соединения', color: '#34d399', fill: true },
  { key: 'udp_pps', label: 'UDP, pps', color: '#f97316' },
  { key: 'conntrack_count', label: 'Записи conntrack', color: '#60a5fa' },
]

const METRICS = [
  { key: 'tcp_new', label: 'Новые TCP за интервал', format: (value) => formatNumber(value, 1) },
  { key: 'udp_pps', label: 'UDP-пакеты', format: (value) => `${formatNumber(value, 1)} pps` },
  { key: 'conntrack_count', label: 'Conntrack', format: (value) => formatNumber(value, 0) },
  { key: 'new_sources', label: 'Новые источники', format: (value) => formatNumber(value, 0) },
]

export default function ConnectionsPage() {
  return (
    <SeriesPage
      endpoint="/metrics/connections"
      series={SERIES}
      metrics={METRICS}
      description="Динамика соединений: скорость установления новых TCP-сессий, UDP-нагрузка, заполнение conntrack и количество новых источников."
    />
  )
}
