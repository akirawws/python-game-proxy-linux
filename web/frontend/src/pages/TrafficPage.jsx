import SeriesPage from '../components/SeriesPage.jsx'
import { formatBps, formatNumber } from '../utils/format.js'

const SERIES = [
  { key: 'in_pps', label: 'Входящие, pps', color: '#38bdf8', fill: true },
  { key: 'out_pps', label: 'Исходящие, pps', color: '#a78bfa' },
]

const METRICS = [
  { key: 'in_pps', label: 'Входящие пакеты', format: (value) => `${formatNumber(value, 1)} pps` },
  { key: 'out_pps', label: 'Исходящие пакеты', format: (value) => `${formatNumber(value, 1)} pps` },
  { key: 'in_bps', label: 'Входящий трафик', format: formatBps },
  { key: 'out_bps', label: 'Исходящий трафик', format: formatBps },
  { key: 'samples', label: 'Замеров в точке', format: (value) => formatNumber(value, 0) },
]

export default function TrafficPage() {
  return (
    <SeriesPage
      endpoint="/metrics/traffic"
      series={SERIES}
      metrics={METRICS}
      description="Интенсивность входящего и исходящего трафика по защищаемым серверам. Значения агрегированы по интервалам выбранного периода."
    />
  )
}
