import { useRef, useEffect } from 'react'
import Empty from './Empty'

export default function TextOutput({ lines }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])

  if (!lines?.length) return <Empty text="No output yet." />
  return (
    <div
      ref={ref}
      className="bg-slate-900 rounded-xl p-4 font-mono text-xs text-slate-300 h-[520px] overflow-y-auto whitespace-pre-wrap leading-relaxed"
    >
      {lines.map((l, i) => <div key={i}>{l}</div>)}
    </div>
  )
}
