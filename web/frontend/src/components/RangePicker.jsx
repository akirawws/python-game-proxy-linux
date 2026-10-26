import { RANGE_LABELS } from '../utils/format.js'

const RANGES = ['5m', '1h', '24h', '7d']

export default function RangePicker({ value, onChange }) {
  return (
    <div className="segmented" role="group" aria-label="Период">
      {RANGES.map((range) => (
        <button
          key={range}
          type="button"
          className={`segmented__item ${value === range ? 'is-active' : ''}`}
          onClick={() => onChange(range)}
          aria-pressed={value === range}
        >
          {RANGE_LABELS[range]}
        </button>
      ))}
    </div>
  )
}
