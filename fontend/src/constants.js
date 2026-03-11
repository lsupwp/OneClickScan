export const TOOLS = [
  { key: 'path_recon',    label: 'Path Recon',    desc: 'Katana crawler',           icon: '🕷️' },
  { key: 'payload_recon', label: 'Payload Recon', desc: 'Form & param extraction',  icon: '📋' },
  { key: 'gobuster',      label: 'Gobuster',      desc: 'Hidden path discovery',    icon: '🔍' },
  { key: 'whatweb',       label: 'WhatWeb',       desc: 'Tech fingerprinting',      icon: '🌐' },
  { key: 'nuclei',        label: 'Nuclei',        desc: 'CVE template scan',        icon: '⚡' },
  { key: 'nmap',          label: 'Nmap',          desc: 'Port & service scan',      icon: '🛡️' },
  { key: 'subfinder',     label: 'Subfinder',     desc: 'Subdomain enumeration',    icon: '🔗' },
  { key: 'davtest',       label: 'DAVTest',       desc: 'WebDAV upload probe',      icon: '📂' },
  { key: 'ai_triage',     label: 'AI Triage',     desc: 'Gemini AI analysis',       icon: '✨' },
  { key: 'run_exploit',   label: 'Full Exploit',  desc: 'Scan → brute → post-auth', icon: '🚀' },
]

// maps section header keywords → tool key
// NOTE: order matters — more specific patterns first
export const SECTION_MAP = [
  { match: /PATH RECON/i,                         tool: 'path_recon'    },
  // payload_recon: standalone flag AND sub-sections inside run_exploit pipeline
  { match: /PAYLOAD RECON|CATEGORY\s+[12]|HTML FORMS|URL QUERY/i, tool: 'payload_recon' },
  { match: /GOBUSTER/i,                           tool: 'gobuster'      },
  { match: /WHATWEB/i,                            tool: 'whatweb'       },
  { match: /NUCLEI/i,                             tool: 'nuclei'        },
  { match: /NMAP/i,                               tool: 'nmap'          },
  { match: /SUBFINDER/i,                          tool: 'subfinder'     },
  { match: /DAVTEST/i,                            tool: 'davtest'       },
  // triage: "AUTO TRIAGE", "AI TRIAGE ROUND 2", "TRIAGE"
  { match: /TRIAGE/i,                             tool: 'ai_triage'     },
  // run_exploit: phase banners and brute/auth steps
  { match: /PRE.AUTH|POST.AUTH|EXPLOIT|BRUTE FORCE|AUTHENTICATE/i, tool: 'run_exploit' },
]

// sub-tools that appear inside the --run-exploit pipeline
export const EXPLOIT_SUBTOOLS = ['path_recon', 'payload_recon', 'gobuster', 'davtest', 'ai_triage']

export const SEV_COLOR = {
  critical: 'text-red-600 font-bold',
  high:     'text-orange-500 font-semibold',
  medium:   'text-yellow-600',
  low:      'text-blue-500',
  info:     'text-gray-500',
}

export function toolFor(line) {
  for (const { match, tool } of SECTION_MAP) {
    if (match.test(line)) return tool
  }
  return null
}
