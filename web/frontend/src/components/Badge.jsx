const TONES = {
  success: 'badge--success',
  danger: 'badge--danger',
  warning: 'badge--warning',
  critical: 'badge--critical',
  info: 'badge--info',
  neutral: 'badge--neutral',
}

export default function Badge({ tone = 'neutral', children, title }) {
  return (
    <span className={`badge ${TONES[tone] || TONES.neutral}`} title={title}>
      {children}
    </span>
  )
}
