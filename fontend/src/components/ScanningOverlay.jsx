import { TOOLS } from '../constants'

export default function ScanningOverlay({ currentTool }) {
  const tool = TOOLS.find(t => t.key === currentTool)
  return (
    <div className="flex flex-col items-center justify-center h-full select-none gap-6">
      {/* radar rings */}
      <div className="relative flex items-center justify-center w-32 h-32">
        <div className="absolute w-32 h-32 rounded-full border-2 border-blue-200 animate-ping opacity-30" />
        <div
          className="absolute w-24 h-24 rounded-full border-2 border-blue-300 animate-ping opacity-40"
          style={{ animationDelay: '0.3s' }}
        />
        <div
          className="absolute w-16 h-16 rounded-full border-2 border-blue-400 animate-ping opacity-50"
          style={{ animationDelay: '0.6s' }}
        />
        <div className="relative w-10 h-10 rounded-full bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-300">
          <div className="w-10 h-10 rounded-full border-4 border-blue-200 border-t-white animate-spin absolute" />
          <span className="text-white text-lg relative z-10">🛡️</span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-slate-700 font-bold text-base">Scanning…</div>
        {tool && (
          <div className="text-blue-600 text-sm mt-1 animate-pulse font-medium">
            {tool.icon} {tool.label}
          </div>
        )}
        <div className="text-slate-400 text-xs mt-2">
          Results will appear as tabs when each tool finishes
        </div>
      </div>
    </div>
  )
}
