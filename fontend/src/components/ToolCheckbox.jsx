export default function ToolCheckbox({ tool, checked, onChange, disabled }) {
  return (
    <label className={`flex items-start gap-3 p-3 rounded-xl cursor-pointer transition-all
      ${checked
        ? 'bg-blue-600 text-white shadow-md shadow-blue-200'
        : 'bg-white text-slate-700 hover:bg-slate-50 border border-slate-200'}
      ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
    `}>
      <input
        type="checkbox"
        className="mt-0.5 accent-white"
        checked={checked}
        onChange={() => !disabled && onChange(tool.key)}
        disabled={disabled}
      />
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 font-semibold text-sm leading-tight">
          <span>{tool.icon}</span>
          <span>{tool.label}</span>
        </div>
        <div className={`text-xs mt-0.5 truncate ${checked ? 'text-blue-100' : 'text-slate-400'}`}>
          {tool.desc}
        </div>
      </div>
    </label>
  )
}
