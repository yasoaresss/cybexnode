'use client'

import { useEffect, useState } from 'react'
import type { Incident } from '@/types/incident'

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5277'
const CVE_RE   = /CVE-\d{4}-\d+/i

interface CveEntry {
  id: string
  cveId: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  description: string
  severity: string
  requiredAction: string
  dueDate: string | null
  createdAt: string
}

interface Props {
  incident: Incident
  onClose: () => void
}

const SEV_COLOR: Record<string, string> = {
  Critical: '#ff2056',
  High:     '#ff6b00',
  Medium:   '#f5c400',
  Low:      '#00ff88',
}

function attackDescription(attackType: string): string {
  const t = attackType.toLowerCase()
  if (t.includes('brute force') || t.includes('bruteforce'))
    return 'Tentativa de acesso por força bruta detectada. Múltiplas tentativas de autenticação registradas em curto período de tempo.'
  if (t.includes('ddos') || t.includes('flood') || t.includes('syn'))
    return 'Ataque de negação de serviço distribuído (DDoS) detectado. Volume anormal de tráfego sobrecarregando recursos da rede.'
  if (t.includes('sql injection') || t.includes('sql'))
    return 'Tentativa de injeção SQL detectada. Possível extração ou manipulação de dados no banco de dados.'
  if (t.includes('port scan') || t.includes('scan'))
    return 'Varredura de portas detectada. Reconhecimento da superfície de ataque e identificação de serviços expostos.'
  if (t.includes('malware') || t.includes('c2') || t.includes('command'))
    return 'Atividade de malware ou servidor C2 detectado. Possível comprometimento e exfiltração de dados.'
  if (t.includes('phishing'))
    return 'Tentativa de phishing detectada. E-mail ou página maliciosa visando roubo de credenciais.'
  if (t.includes('recon'))
    return 'Atividade de reconhecimento detectada. Coleta de informações sobre infraestrutura alvo.'
  return 'Atividade maliciosa detectada. Análise detalhada do incidente em andamento.'
}

export default function IncidentDrawer({ incident, onClose }: Props) {
  const [cve,        setCve]        = useState<CveEntry | null>(null)
  const [cveLoading, setCveLoading] = useState(false)
  const [cveError,   setCveError]   = useState(false)

  // Extract CVE ID from attackType if present
  const cveMatch = CVE_RE.exec(incident.attackType)
  const cveId    = cveMatch ? cveMatch[0].toUpperCase() : null

  useEffect(() => {
    if (!cveId) return
    setCveLoading(true)
    setCveError(false)
    fetch(`${API_BASE}/api/cve/${cveId}`)
      .then(r => {
        if (!r.ok) throw new Error('not found')
        return r.json() as Promise<CveEntry>
      })
      .then(data => { setCve(data); setCveLoading(false) })
      .catch(() => { setCveError(true); setCveLoading(false) })
  }, [cveId])

  const sevColor = SEV_COLOR[incident.severity] ?? '#8b949e'

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 8000,
          background: 'rgba(0,0,0,0.55)',
        }}
      />

      {/* Drawer */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, zIndex: 8001,
        width: 400, background: '#161b22',
        borderLeft: '1px solid #30363d',
        display: 'flex', flexDirection: 'column',
        fontFamily: 'Arial, sans-serif', fontSize: 13, color: '#c9d1d9',
        overflowY: 'auto',
      }}>
        {/* Header */}
        <div style={{
          padding: '14px 16px', borderBottom: '1px solid #21262d',
          display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
          background: '#0d1117',
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 9, color: '#6e7681', textTransform: 'uppercase', letterSpacing: 1 }}>
              Detalhe do Incidente
            </div>
            <div style={{
              fontSize: 13, fontWeight: 'bold', color: sevColor,
              marginTop: 2, lineHeight: 1.3,
            }}>
              {incident.attackType}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none', color: '#6e7681',
              cursor: 'pointer', fontSize: 18, padding: 4, lineHeight: 1,
            }}
          >
            ✕
          </button>
        </div>

        {/* Severity badge */}
        <div style={{ padding: '10px 16px 0' }}>
          <span style={{
            padding: '3px 10px', fontSize: 10, fontFamily: 'monospace',
            fontWeight: 'bold', borderRadius: 3,
            background: sevColor + '22', color: sevColor, border: `1px solid ${sevColor}`,
            boxShadow: `0 0 6px ${sevColor}44`,
          }}>
            {incident.severity?.toUpperCase() ?? 'UNKNOWN'}
          </span>
          {incident.dataSource && (
            <span style={{
              marginLeft: 6, padding: '3px 8px', fontSize: 10,
              background: '#21262d', color: '#8b949e', border: '1px solid #30363d', borderRadius: 3,
            }}>
              {incident.dataSource}
            </span>
          )}
        </div>

        {/* Fields */}
        <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <Field label="IP Origem"     value={incident.sourceIp}    mono />
          <Field label="País"          value={incident.sourceCountry || '—'} />
          {incident.destinationPort ? <Field label="Porta Destino" value={String(incident.destinationPort)} mono /> : null}
          {incident.protocol         ? <Field label="Protocolo"    value={incident.protocol} mono /> : null}
          <Field
            label="Timestamp"
            value={new Date(incident.createdAt).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) + ' BRT'}
          />
        </div>

        <Divider />

        {/* CVE section or generic description */}
        {cveId ? (
          <div style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: 9, color: '#6e7681', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
              Contexto de Vulnerabilidade
            </div>

            {cveLoading && (
              <div style={{ color: '#6e7681', fontSize: 11, display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 14, height: 14, border: '2px solid #30363d',
                  borderTopColor: '#58a6ff', borderRadius: '50%',
                  animation: 'spin 0.8s linear infinite', flexShrink: 0,
                }} />
                Buscando dados do {cveId}…
              </div>
            )}

            {!cveLoading && cveError && (
              <div style={{
                background: '#21262d', borderRadius: 4, padding: '10px 12px',
                border: '1px solid #30363d', fontSize: 11, color: '#8b949e',
              }}>
                <div style={{ color: '#f5c400', marginBottom: 4, fontWeight: 'bold' }}>{cveId}</div>
                CVE não encontrada na base CISA local.
              </div>
            )}

            {!cveLoading && cve && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {/* CVE ID + name */}
                <div style={{ background: '#0d1117', borderRadius: 4, padding: '10px 12px', border: '1px solid #30363d' }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#58a6ff', marginBottom: 4 }}>
                    {cve.cveId}
                  </div>
                  <div style={{ fontSize: 12, fontWeight: 'bold', color: '#c9d1d9', lineHeight: 1.4 }}>
                    {cve.vulnerabilityName}
                  </div>
                </div>

                <Field label="Fornecedor / Produto" value={`${cve.vendorProject} — ${cve.product}`} />

                {/* Description */}
                <div>
                  <div style={{ fontSize: 9, color: '#6e7681', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>
                    Descrição
                  </div>
                  <div style={{ fontSize: 11, color: '#8b949e', lineHeight: 1.6 }}>{cve.description}</div>
                </div>

                {/* Required Action — highlighted in green */}
                <div style={{
                  background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.3)',
                  borderRadius: 4, padding: '10px 12px',
                }}>
                  <div style={{
                    fontSize: 9, color: '#00ff88', textTransform: 'uppercase',
                    letterSpacing: 1, marginBottom: 6, fontWeight: 'bold',
                  }}>
                    Como se Proteger
                  </div>
                  <div style={{ fontSize: 11, color: '#c9d1d9', lineHeight: 1.6 }}>{cve.requiredAction}</div>
                </div>

                {cve.dueDate && (
                  <Field
                    label="Prazo CISA"
                    value={new Date(cve.dueDate).toLocaleDateString('pt-BR')}
                  />
                )}
              </div>
            )}
          </div>
        ) : (
          <div style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: 9, color: '#6e7681', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
              Descrição do Ataque
            </div>
            <div style={{ fontSize: 11, color: '#8b949e', lineHeight: 1.6 }}>
              {attackDescription(incident.attackType)}
            </div>
          </div>
        )}
      </div>
    </>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: '#6e7681', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ fontSize: 12, color: '#c9d1d9', fontFamily: mono ? 'monospace' : undefined }}>
        {value}
      </div>
    </div>
  )
}

function Divider() {
  return <div style={{ height: 1, background: '#21262d', margin: '0 16px' }} />
}
