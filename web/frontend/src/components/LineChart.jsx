import {
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js'
import { useMemo } from 'react'
import { Line } from 'react-chartjs-2'

import { formatNumber, formatTime } from '../utils/format.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend)

const GRID = 'rgba(148, 163, 184, 0.14)'
const TICKS = '#93a4bb'

export default function LineChart({ points, xKey = 'ts', series = [], height = 300 }) {
  const chartData = useMemo(() => {
    const rows = points || []
    return {
      labels: rows.map((point) => formatTime(point[xKey])),
      datasets: series.map((item) => ({
        label: item.label,
        data: rows.map((point) => point[item.key] ?? null),
        borderColor: item.color,
        backgroundColor: `${item.color}22`,
        fill: Boolean(item.fill),
        tension: 0.25,
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 12,
        spanGaps: true,
      })),
    }
  }, [points, series, xKey])

  const options = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: TICKS, boxWidth: 12, boxHeight: 12, usePointStyle: true },
        },
        tooltip: {
          backgroundColor: '#0f172a',
          borderColor: '#27364d',
          borderWidth: 1,
          titleColor: '#e2e8f0',
          bodyColor: '#cbd5e1',
          callbacks: {
            label: (context) =>
              `${context.dataset.label}: ${formatNumber(context.parsed.y, 2)}`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: GRID, drawTicks: false },
          ticks: { color: TICKS, maxTicksLimit: 8, maxRotation: 0, autoSkip: true },
        },
        y: {
          beginAtZero: true,
          grid: { color: GRID, drawTicks: false },
          ticks: {
            color: TICKS,
            maxTicksLimit: 6,
            callback: (value) => formatNumber(value, 1),
          },
        },
      },
    }),
    [],
  )

  return (
    <div className="chart" style={{ height }}>
      <Line data={chartData} options={options} />
    </div>
  )
}
