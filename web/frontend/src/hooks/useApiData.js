import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Загружает данные через API и (опционально) обновляет их по таймеру.
 * deps — зависимости загрузчика, как в useEffect.
 */
export function useApiData(loader, deps = [], options = {}) {
  const { refreshMs = 0, enabled = true } = options
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(enabled)
  const [updatedAt, setUpdatedAt] = useState(null)
  const sequence = useRef(0)

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(async () => {
    if (!enabled) return
    const id = ++sequence.current
    try {
      const result = await loader()
      if (id !== sequence.current) return
      setData(result)
      setError(null)
      setUpdatedAt(new Date())
    } catch (err) {
      if (id !== sequence.current) return
      setError(err)
    } finally {
      if (id === sequence.current) setLoading(false)
    }
  }, [...deps, enabled])

  useEffect(() => {
    if (!enabled) return undefined
    setLoading(true)
    run()
    if (!refreshMs) return undefined
    const timer = setInterval(run, refreshMs)
    return () => clearInterval(timer)
  }, [run, refreshMs, enabled])

  return { data, error, loading, updatedAt, reload: run }
}
