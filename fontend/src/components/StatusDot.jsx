export default function StatusDot({ status }) {
  if (status === 'running')
    return <span className="inline-block w-2 h-2 rounded-full bg-blue-500 animate-pulse mr-1.5" />
  if (status === 'done')
    return <span className="inline-block w-2 h-2 rounded-full bg-green-500 mr-1.5" />
  return null
}
