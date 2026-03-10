'use client'

import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { useSignalR } from '@/hooks/useSignalR'
import type { Incident as SignalRIncident } from '@/types/incident'
import IncidentDrawer from '@/components/IncidentDrawer'
import 'leaflet/dist/leaflet.css'
import { MapContainer, TileLayer, useMap } from 'react-leaflet'
import L from 'leaflet'
import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
} from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler)

// ─── Types ────────────────────────────────────────────────────────────────────
interface Attack {
  id: string; lat: number; lng: number; city: string; state: string
  type: string; sev: string; src: string; port: number; country: string
  dataSource?: string
  createdAt?: string
}

const SAO_PAULO = { lat: -23.5505, lng: -46.6333 }
const API_BASE  = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5277'
interface TickItem   { cls: string; txt: string }
interface Stats      { atkMin: number; atkTotal: number; atkIps: number; atkCountries: number; crits: number; cntCrit: number; cntHigh: number; cntMedium: number; cntLow: number; cntHp: number }
interface StateInfo  { name: string; abbr: string; region: string }
interface StateStats {
  state: string; name: string; total: number
  severity: { critical: number; high: number; medium: number; low: number }
  topTypes: { type: string; count: number }[]
  topIPs:   { ip: string; count: number }[]
  hourlyData: number[]
}
interface SelectedState { code: string; name: string }

// ─── Severity palette ─────────────────────────────────────────────────────────
const SEV: Record<string, { color: string; glow: string; size: number; label: string }> = {
  critical: { color: '#ff2056', glow: 'rgba(255,32,86,0.6)',   size: 12, label: 'CRÍTICO'  },
  high:     { color: '#ff6b00', glow: 'rgba(255,107,0,0.6)',   size: 10, label: 'ALTO'     },
  medium:   { color: '#f5c400', glow: 'rgba(245,196,0,0.5)',   size: 8,  label: 'MÉDIO'    },
  low:      { color: '#00ff88', glow: 'rgba(0,255,136,0.4)',   size: 6,  label: 'BAIXO'    },
  hp:       { color: '#00cfff', glow: 'rgba(0,207,255,0.5)',   size: 8,  label: 'HONEYPOT' },
}

function badgeStyle(sev: string): React.CSSProperties {
  const s = SEV[sev] ?? SEV.low
  return { background: s.color + '26', color: s.color, border: `1px solid ${s.color}` }
}
function sevColor(sev: string): string { return SEV[sev]?.color ?? '#30363d' }

// ─── SignalR → Dashboard mappers ──────────────────────────────────────────────
const SEV_MAP: Record<string, string> = { Critical:'critical', High:'high', Medium:'medium', Low:'low' }

function isHoneypot(dataSource?: string | null): boolean {
  return dataSource === 'HoneypotSP' || dataSource === 'Cowrie'
}

function isThreatIntel(dataSource?: string | null): boolean {
  return dataSource === 'OTX' || dataSource === 'AbuseIPDB' || dataSource === 'FeodoTracker'
    || dataSource === 'DShield' || dataSource === 'HoneyDB' || dataSource === 'GreyNoise'
}

const COWRIE_TYPE_MAP: Record<string, string> = {
  'cowrie.login.failed':    'Brute Force — Login Failed',
  'cowrie.login.success':   'Brute Force — Login Success',
  'cowrie.command.input':   'Command Execution',
  'cowrie.command.failed':  'Command Execution',
  'cowrie.session.connect': 'Reconnaissance',
  'cowrie.session.closed':  'Session Closed',
  'cowrie.session.file_download': 'Malware Download',
  'cowrie.session.file_upload':   'File Upload',
  'cowrie.direct-tcpip.data':     'Port Forwarding',
  'cowrie.direct-tcpip':          'Port Forwarding',
}

function resolveAttackType(inc: SignalRIncident): string {
  if (!isHoneypot(inc.dataSource)) return inc.attackType ?? 'Unknown'
  return COWRIE_TYPE_MAP[inc.attackType]
    ?? inc.attackType?.replace(/^cowrie\./, '')
    ?? 'Unknown'
}

function incidentToAttack(inc: SignalRIncident): Attack {
  return {
    id:         String(inc.id),
    lat:        inc.latitude,  lng: inc.longitude,
    city:       inc.sourceCity, state: '',
    type:       resolveAttackType(inc),
    sev:        SEV_MAP[inc.severity] ?? 'low',
    src:        inc.sourceIp,
    port:       inc.destinationPort,
    country:    inc.sourceCountry,
    dataSource: inc.dataSource,
  }
}

function formatRelTime(iso: string): string {
  const utc  = iso.endsWith('Z') ? iso : iso + 'Z'
  const secs = Math.floor((Date.now() - new Date(utc).getTime()) / 1000)
  if (secs < 60)   return 'agora'
  if (secs < 3600) return `${Math.floor(secs / 60)}min atrás`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h atrás`
  return `${Math.floor(secs / 86400)}d atrás`
}

function incidentDetail(inc: SignalRIncident): string {
  const port    = inc.destinationPort ?? 22
  const country = inc.sourceCountry ? ` (${inc.sourceCountry})` : ''
  return `${inc.sourceIp}${country} → São Paulo/SP:${port}`
}

function incidentToFeedItem(inc: SignalRIncident) {
  return {
    id:        String(inc.id),
    sev:       SEV_MAP[inc.severity] ?? 'low',
    type:      resolveAttackType(inc),
    detail:    incidentDetail(inc),
    createdAt: inc.createdAt,
    rawInc:    inc,
  }
}

// ─── Static fallbacks (empty — no mock data) ──────────────────────────────────
const ATTACKS: Attack[]    = []
const TICKS: TickItem[]    = []
const ATTACK_TYPES: { name: string; pct: number; color: string }[]       = []
const TOP_ORIGINS: { code: string; name: string; count: number }[]        = []

const USERS: Record<string, { pass: string; role: string }> = {
  admin:    { pass:'admin123',    role:'Administrador' },
  analista: { pass:'analista123', role:'Analista'      },
}

const ATTACK_TYPE_COLORS = ['#ff2056','#ff6b00','#f5c400','#00cfff','#bc8cff','#00ff88','#8b949e']

const COUNTRY_NAMES: Record<string, string> = {
  US:'Estados Unidos', CN:'China',         RU:'Rússia',         BR:'Brasil',
  DE:'Alemanha',       FR:'França',         GB:'Reino Unido',    NL:'Países Baixos',
  IN:'Índia',          KR:'Coreia do Sul',  JP:'Japão',          IR:'Irã',
  UA:'Ucrânia',        VN:'Vietnã',         HK:'Hong Kong',      SG:'Singapura',
  TR:'Turquia',        AR:'Argentina',      MX:'México',         PL:'Polônia',
  IT:'Itália',         ES:'Espanha',        CA:'Canadá',         AU:'Austrália',
  TH:'Tailândia',      ID:'Indonésia',      PK:'Paquistão',      BD:'Bangladesh',
  NG:'Nigéria',        IL:'Israel',         RO:'Romênia',        BG:'Bulgária',
  CZ:'República Tcheca', SE:'Suécia',       NO:'Noruega',        FI:'Finlândia',
  PT:'Portugal',       CL:'Chile',          CO:'Colômbia',       PE:'Peru',
  ZA:'África do Sul',  EG:'Egito',          SA:'Arábia Saudita', AE:'Emirados Árabes',
}

function countryDisplayName(code: string): string {
  return COUNTRY_NAMES[code] ?? code
}

// ─── Map constants ────────────────────────────────────────────────────────────
const STATE_INFO: Record<string, StateInfo> = {
  '11':{ name:'Rondônia',            abbr:'RO', region:'Norte'        },
  '12':{ name:'Acre',                abbr:'AC', region:'Norte'        },
  '13':{ name:'Amazonas',            abbr:'AM', region:'Norte'        },
  '14':{ name:'Roraima',             abbr:'RR', region:'Norte'        },
  '15':{ name:'Pará',                abbr:'PA', region:'Norte'        },
  '16':{ name:'Amapá',               abbr:'AP', region:'Norte'        },
  '17':{ name:'Tocantins',           abbr:'TO', region:'Norte'        },
  '21':{ name:'Maranhão',            abbr:'MA', region:'Nordeste'     },
  '22':{ name:'Piauí',               abbr:'PI', region:'Nordeste'     },
  '23':{ name:'Ceará',               abbr:'CE', region:'Nordeste'     },
  '24':{ name:'Rio Grande do Norte', abbr:'RN', region:'Nordeste'     },
  '25':{ name:'Paraíba',             abbr:'PB', region:'Nordeste'     },
  '26':{ name:'Pernambuco',          abbr:'PE', region:'Nordeste'     },
  '27':{ name:'Alagoas',             abbr:'AL', region:'Nordeste'     },
  '28':{ name:'Sergipe',             abbr:'SE', region:'Nordeste'     },
  '29':{ name:'Bahia',               abbr:'BA', region:'Nordeste'     },
  '31':{ name:'Minas Gerais',        abbr:'MG', region:'Sudeste'      },
  '32':{ name:'Espírito Santo',      abbr:'ES', region:'Sudeste'      },
  '33':{ name:'Rio de Janeiro',      abbr:'RJ', region:'Sudeste'      },
  '35':{ name:'São Paulo',           abbr:'SP', region:'Sudeste'      },
  '41':{ name:'Paraná',              abbr:'PR', region:'Sul'          },
  '42':{ name:'Santa Catarina',      abbr:'SC', region:'Sul'          },
  '43':{ name:'Rio Grande do Sul',   abbr:'RS', region:'Sul'          },
  '50':{ name:'Mato Grosso do Sul',  abbr:'MS', region:'Centro-Oeste' },
  '51':{ name:'Mato Grosso',         abbr:'MT', region:'Centro-Oeste' },
  '52':{ name:'Goiás',               abbr:'GO', region:'Centro-Oeste' },
  '53':{ name:'Distrito Federal',    abbr:'DF', region:'Centro-Oeste' },
}

const STATE_REGION: Record<string, string> = Object.fromEntries(
  Object.values(STATE_INFO).map(s => [s.abbr, s.region])
)

const REGION_VIEW: Record<string, { center: [number,number]; zoom: number }> = {
  'Todas':        { center:[-14.2,-51.9], zoom:4 },
  'Norte':        { center:[-5,  -62   ], zoom:5 },
  'Nordeste':     { center:[-8,  -40   ], zoom:6 },
  'Centro-Oeste': { center:[-15, -53   ], zoom:6 },
  'Sudeste':      { center:[-21, -44   ], zoom:6 },
  'Sul':          { center:[-28, -51   ], zoom:6 },
}

const WORLD_ATLAS_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-50m.json'
const STATES_URL      = 'https://servicodados.ibge.gov.br/api/v3/malhas/paises/BR?formato=application/vnd.geo+json&qualidade=intermediario&divisao=estadual'
const STATES_FALLBACK = 'https://raw.githubusercontent.com/codeforamerica/click_that_hood/master/public/data/brazil-states.geojson'

// ─── GeoJSON property extractor ───────────────────────────────────────────────
function extractStateCode(props: Record<string, unknown>): { abbr: string; name: string } | null {
  if (props.codarea) {
    const info = STATE_INFO[props.codarea as string]
    if (info) return { abbr: info.abbr, name: info.name }
  }
  const abbr = (props.sigla ?? props.SIGLA ?? props.abbr ?? props.ABBR) as string | undefined
  const name = (props.nome  ?? props.name  ?? props.Name ?? abbr)       as string | undefined
  if (abbr) return { abbr, name: name ?? abbr }
  return null
}

// ─── State stats helpers ──────────────────────────────────────────────────────
async function fetchStateStats(abbr: string, name: string): Promise<StateStats> {
  try {
    const r = await fetch(`${API_BASE}/api/dashboard/stats?state=${abbr}&hours=12`, { signal: AbortSignal.timeout(3000) })
    if (r.ok) {
      const data = await r.json()
      console.log(`[StateStats ${abbr}] API response:`, JSON.stringify(data))
      return {
        state: abbr,
        name,
        total:    data.total ?? 0,
        severity: {
          critical: data.bySeverity?.critical ?? data.bySeverity?.Critical ?? 0,
          high:     data.bySeverity?.high     ?? data.bySeverity?.High     ?? 0,
          medium:   data.bySeverity?.medium   ?? data.bySeverity?.Medium   ?? 0,
          low:      data.bySeverity?.low      ?? data.bySeverity?.Low      ?? 0,
        },
        topTypes:   (data.top3AttackTypes ?? []).map((t: { type: string; count: number } | string) =>
          typeof t === 'string' ? { type: t, count: 0 } : t),
        topIPs:     (data.top3SourceIps   ?? []).map((ip: { ip: string; count: number } | string) =>
          typeof ip === 'string' ? { ip, count: 0 } : ip),
        hourlyData: (data.volumeByHour    ?? []).map((v: { count: number }) => v.count),
      }
    }
  } catch (err) {
    console.error('[StateStats] fetch error', err)
  }
  return {
    state: abbr, name, total: 0,
    severity: { critical: 0, high: 0, medium: 0, low: 0 },
    topTypes: [], topIPs: [], hourlyData: [],
  }
}

// ─── Leaflet style constants ──────────────────────────────────────────────────
const STATE_HIDDEN: L.PathOptions = { color: 'transparent', weight: 1, fillOpacity: 0, opacity: 0 }
const STATE_BASE:   L.PathOptions = { color: '#2a4aaa',     weight: 1, fillOpacity: 0.04, opacity: 0.6 }
const STATE_HOVER:  L.PathOptions = { color: '#58a6ff',     fillOpacity: 0.08 }
const STATE_SEL:    L.PathOptions = { color: '#58a6ff',     weight: 2, fillOpacity: 0.15, opacity: 1 }

function getFeatureStyle(abbr: string | undefined, activeRegion: string, selectedCode: string | null): L.PathOptions {
  if (!abbr) return STATE_HIDDEN
  if (abbr === selectedCode) return STATE_SEL
  if (activeRegion === 'Todas') return STATE_HIDDEN
  return STATE_REGION[abbr] === activeRegion ? STATE_BASE : STATE_HIDDEN
}

// ─── Leaflet sub-components ───────────────────────────────────────────────────
function BrazilBorder() {
  const map = useMap()
  useEffect(() => {
    let layer: L.GeoJSON | null = null
    const ctrl  = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 10000)
    async function load() {
      try {
        if (!(window as unknown as Record<string, unknown>).topojson) {
          await new Promise<void>((res, rej) => {
            const s = document.createElement('script')
            s.src = 'https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js'
            s.onload = () => res(); s.onerror = () => rej(new Error('topojson load failed'))
            document.head.appendChild(s)
          })
        }
        const r = await fetch(WORLD_ATLAS_URL, { signal: ctrl.signal })
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const topo = await r.json()
        if (ctrl.signal.aborted) return
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const topojson = (window as any).topojson
        const geo    = topojson.feature(topo, topo.objects.countries)
        const brazil = { ...geo, features: geo.features.filter((f: { id: string }) => f.id === '076') }
        layer = L.geoJSON(brazil, { style: { color: '#3d6aff', weight: 2, fillOpacity: 0, opacity: 0.8 } })
        layer.addTo(map)
      } catch (err) {
        if (ctrl.signal.aborted) return
        console.error('[CybexNode] BrazilBorder: falha ao carregar contorno', err)
      } finally { clearTimeout(timer) }
    }
    load()
    return () => { ctrl.abort(); clearTimeout(timer); if (layer) { map.removeLayer(layer); layer = null } }
  }, [map])
  return null
}

function StatesLayer({ selectedCode, activeRegion, onStateClick }: {
  selectedCode: string | null; activeRegion: string; onStateClick: (abbr: string, name: string) => void
}) {
  const map       = useMap()
  const layerRef  = useRef<L.GeoJSON | null>(null)
  const cbRef     = useRef(onStateClick)
  const selRef    = useRef(selectedCode)
  const regionRef = useRef(activeRegion)

  useEffect(() => { cbRef.current    = onStateClick }, [onStateClick])
  useEffect(() => { selRef.current   = selectedCode  }, [selectedCode])
  useEffect(() => { regionRef.current = activeRegion }, [activeRegion])

  useEffect(() => {
    if (!layerRef.current) return
    layerRef.current.eachLayer(l => {
      const fl   = l as L.Path & { feature?: { properties?: Record<string, unknown> } }
      const info = extractStateCode(fl.feature?.properties ?? {})
      fl.setStyle(getFeatureStyle(info?.abbr, activeRegion, selectedCode))
    })
  }, [selectedCode, activeRegion])

  useEffect(() => {
    const ctrl  = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 12000)
    async function load() {
      for (const url of [STATES_URL, STATES_FALLBACK]) {
        try {
          const r = await fetch(url, { signal: ctrl.signal })
          if (!r.ok) continue
          const data = await r.json()
          if (ctrl.signal.aborted) return
          const layer = L.geoJSON(data, {
            style: () => STATE_HIDDEN,
            onEachFeature(feature, fl) {
              fl.on({
                click() {
                  const info = extractStateCode(feature.properties as Record<string, unknown>)
                  if (info) cbRef.current(info.abbr, info.name)
                },
                mouseover(e: L.LeafletMouseEvent) {
                  const info = extractStateCode((e.target.feature?.properties ?? {}) as Record<string, unknown>)
                  const currentStyle = getFeatureStyle(info?.abbr, regionRef.current, selRef.current)
                  if (currentStyle.opacity === 0 || info?.abbr === selRef.current) return
                  e.target.setStyle(STATE_HOVER);(e.target as L.Path).bringToFront()
                },
                mouseout(e: L.LeafletMouseEvent) {
                  const info = extractStateCode((e.target.feature?.properties ?? {}) as Record<string, unknown>)
                  e.target.setStyle(getFeatureStyle(info?.abbr, regionRef.current, selRef.current))
                },
              })
            },
          }).addTo(map)
          layerRef.current = layer
          layer.eachLayer(l => {
            const fl   = l as L.Path & { feature?: { properties?: Record<string, unknown> } }
            const info = extractStateCode(fl.feature?.properties ?? {})
            fl.setStyle(getFeatureStyle(info?.abbr, regionRef.current, selRef.current))
          })
          return
        } catch (err) {
          if (ctrl.signal.aborted) return
          console.warn(`[CybexNode] StatesLayer: falha em ${url}`, err)
        }
      }
    }
    load().finally(() => clearTimeout(timer))
    return () => {
      ctrl.abort(); clearTimeout(timer)
      if (layerRef.current) { map.removeLayer(layerRef.current); layerRef.current = null }
    }
  }, [map])
  return null
}

function MapController({ region }: { region: string }) {
  const map    = useMap()
  const isFirst = useRef(true)
  useEffect(() => {
    if (isFirst.current) { isFirst.current = false; return }
    const v = REGION_VIEW[region]
    if (v) map.flyTo(v.center, v.zoom, { duration: 1.2 })
  }, [map, region])
  return null
}

// ─── Bezier arc helper ────────────────────────────────────────────────────────
function getBezierPoints(src: [number, number], dst: [number, number], steps = 28): [number, number][] {
  const [lat1, lng1] = src
  const [lat2, lng2] = dst
  // Control point elevated above midpoint — creates the upward arc
  const ctrlLat = (lat1 + lat2) / 2 + Math.max(Math.abs(lat1 - lat2) * 0.5, 4)
  const ctrlLng = (lng1 + lng2) / 2
  return Array.from({ length: steps + 1 }, (_, i) => {
    const t = i / steps, u = 1 - t
    return [
      u * u * lat1 + 2 * u * t * ctrlLat + t * t * lat2,
      u * u * lng1 + 2 * u * t * ctrlLng + t * t * lng2,
    ] as [number, number]
  })
}

// ─── Attack overlay (Kaspersky/CheckPoint style) ──────────────────────────────
const AttackLines = React.memo(function AttackLines({ attacks }: { attacks: Attack[] }) {
  const map     = useMap()
  const seenRef = useRef<Set<string>>(new Set())

  useEffect(() => {
    for (const a of attacks) {
      // Marca como visto mesmo sem animar (evita animar histórico no reload)
      if (seenRef.current.has(a.id)) continue
      seenRef.current.add(a.id)

      if (!(a.dataSource === 'HoneypotSP' || a.dataSource === 'Cowrie')) continue
      if (!a.lat || !a.lng) continue
      if (Math.abs(a.lat - SAO_PAULO.lat) < 0.5 && Math.abs(a.lng - SAO_PAULO.lng) < 0.5) continue

      // Só anima ataques recentes (últimos 15s) — não anima histórico do carregamento inicial
      const ts  = a.createdAt ? new Date(a.createdAt.endsWith('Z') ? a.createdAt : a.createdAt + 'Z').getTime() : NaN
      const age = isNaN(ts) ? 0 : Date.now() - ts
      if (age > 15_000) continue

      const color = SEV[a.sev?.toLowerCase()]?.color ?? '#8b949e'
      const src: [number, number] = [a.lat, a.lng]
      const dst: [number, number] = [SAO_PAULO.lat, SAO_PAULO.lng]

      console.log(`[AttackLines] plotando arco: ${a.id} | ${a.src} → SP | sev=${a.sev} | age=${age}ms`)

      // Arco curvo Bezier
      const arc = L.polyline(getBezierPoints(src, dst), {
        color, weight: 1.2, interactive: false, className: 'attack-arc',
      }).addTo(map)

      // Bolinha na origem — divIcon para suportar CSS opacity transition
      const dotEl = document.createElement('div')
      dotEl.style.cssText = `width:7px;height:7px;border-radius:50%;background:${color};box-shadow:0 0 6px ${color};opacity:1;pointer-events:none;`
      const dot = L.marker(src, {
        icon: L.divIcon({ className: '', html: dotEl, iconSize: [7, 7], iconAnchor: [3.5, 3.5] }),
        interactive: false,
      }).addTo(map)

      // Bolinha em São Paulo — divIcon para suportar CSS opacity transition
      const spDotEl = document.createElement('div')
      spDotEl.style.cssText = `width:8px;height:8px;border-radius:50%;background:${color};box-shadow:0 0 8px ${color};opacity:0.8;pointer-events:none;`
      const spDot = L.marker(dst, {
        icon: L.divIcon({ className: '', html: spDotEl, iconSize: [8, 8], iconAnchor: [4, 4] }),
        interactive: false,
      }).addTo(map)

      // Dois rAF garantem que o Leaflet renderizou o SVG antes de ler getTotalLength()
      requestAnimationFrame(() => requestAnimationFrame(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const path = (arc as any)._path as SVGPathElement | null
        if (!path) { arc.remove(); dot.remove(); spDot.remove(); return }

        const len = Math.ceil(path.getTotalLength())
        if (len === 0) { arc.remove(); dot.remove(); spDot.remove(); return }

        // Estado inicial: arco invisível pronto para desenhar
        path.style.strokeDasharray  = String(len)
        path.style.strokeDashoffset = String(len)
        path.style.opacity          = '0'
        path.style.filter           = `drop-shadow(0 0 3px ${color})`

        // t=0 → t=1.5s  — arco cresce da origem até SP
        requestAnimationFrame(() => {
          path.style.transition      = 'stroke-dashoffset 1.5s ease-out, opacity 0.1s'
          path.style.strokeDashoffset = '0'
          path.style.opacity          = '0.9'
        })

        // t=1.5s → t=2.5s — snake: arco some da origem para SP
        setTimeout(() => {
          path.style.transition       = 'stroke-dashoffset 1s ease-in'
          path.style.strokeDashoffset = String(-len)

          // Anel expandindo em SP ao receber o ataque
          let r = 4
          const ring = L.circleMarker(dst, {
            radius: r, color, fillColor: 'transparent', fillOpacity: 0,
            opacity: 0.9, weight: 1.5, interactive: false,
          }).addTo(map)
          const expand = setInterval(() => {
            r += 1.5
            ring.setRadius(r)
            ring.setStyle({ opacity: Math.max(0, 0.9 - (r - 4) / 16) })
            if (r >= 20) { clearInterval(expand); ring.remove() }
          }, 40)
        }, 1500)

        // t=2.5s → t=3s — fade out arco + bolinha origem + bolinha SP
        setTimeout(() => {
          path.style.transition    = 'opacity 0.5s ease-out'
          path.style.opacity       = '0'
          dotEl.style.transition   = 'opacity 0.5s'
          dotEl.style.opacity      = '0'
          spDotEl.style.transition = 'opacity 0.5s'
          spDotEl.style.opacity    = '0'
        }, 2500)

        // t=3.1s — remove do DOM (arco + ambas as bolinhas juntas)
        const removeAll = () => { arc.remove(); dot.remove(); spDot.remove() }
        setTimeout(removeAll, 3100)
      }))
    }
  }, [attacks, map])

  return null
})

// ─── State detail panel ───────────────────────────────────────────────────────
function StateDetailPanel({ stats, loading, name, noData, onClose }: {
  stats: StateStats | null; loading: boolean; name: string; noData?: boolean; onClose: () => void
}) {
  return (
    <div style={{
      position:'absolute', top:66, right:8, width:268, zIndex:1000,
      background:'rgba(13,17,23,.97)', border:'1px solid #30363d', borderRadius:6,
      padding:'12px 14px', maxHeight:'calc(100% - 100px)', overflowY:'auto',
    }}>
      <div style={{ display:'flex', alignItems:'center', marginBottom:12 }}>
        <div style={{ flex:1 }}>
          <div style={{ fontSize:9, color:'#6e7681', textTransform:'uppercase', letterSpacing:1 }}>Estado selecionado</div>
          <div style={{ fontSize:15, fontWeight:'bold', color:'#58a6ff' }}>{name}</div>
        </div>
        <button onClick={onClose} style={{ background:'none', border:'none', color:'#6e7681', cursor:'pointer', fontSize:16, padding:4, lineHeight:1 }}>✕</button>
      </div>

      {noData ? (
        <div style={{ textAlign:'center', padding:'24px 0', color:'#6e7681', fontSize:11 }}>
          Nenhum ataque registrado neste estado nas últimas 24h
        </div>
      ) : loading ? (
        <div style={{ textAlign:'center', padding:'24px 0', color:'#6e7681', fontSize:11 }}>
          <div style={{ marginBottom:8 }}>Carregando dados…</div>
          <div style={{ width:24, height:24, border:'2px solid #30363d', borderTopColor:'#58a6ff', borderRadius:'50%', animation:'spin 0.8s linear infinite', margin:'0 auto' }} />
        </div>
      ) : stats ? (
        <>
          <div style={{ background:'#161b22', borderRadius:4, padding:'8px 10px', marginBottom:10, borderLeft:'3px solid #58a6ff' }}>
            <div style={{ fontSize:9, color:'#6e7681', textTransform:'uppercase', letterSpacing:1 }}>Total — últimas 12h</div>
            <div style={{ fontSize:22, fontWeight:'bold', color:'#c9d1d9', fontFamily:'monospace' }}>
              {(stats?.total ?? 0).toLocaleString('pt-BR')}
            </div>
          </div>
          <div style={{ fontSize:9, color:'#6e7681', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Severidade</div>
          {([
            ['Crítico', stats?.severity?.critical ?? 0, 'critical'],
            ['Alto',    stats?.severity?.high     ?? 0, 'high'    ],
            ['Médio',   stats?.severity?.medium   ?? 0, 'medium'  ],
            ['Baixo',   stats?.severity?.low      ?? 0, 'low'     ],
          ] as [string, number, string][]).map(([label, val, sev]) => {
            const total = stats?.total ?? 0
            const pct = total > 0 ? Math.round(val / total * 100) : 0
            const col = sevColor(sev)
            return (
              <div key={label} style={{ marginBottom:6 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:2 }}>
                  <span style={{ fontSize:10, color:'#8b949e' }}>{label}</span>
                  <span style={{ fontSize:10, fontFamily:'monospace', color:col }}>
                    {val.toLocaleString('pt-BR')} <span style={{ color:'#6e7681' }}>({pct}%)</span>
                  </span>
                </div>
                <div style={{ height:3, background:'#21262d', borderRadius:2 }}>
                  <div style={{ height:3, width:`${pct}%`, background:col, borderRadius:2, boxShadow:`0 0 4px ${SEV[sev]?.glow}` }} />
                </div>
              </div>
            )
          })}
          <div style={{ fontSize:9, color:'#6e7681', textTransform:'uppercase', letterSpacing:1, margin:'10px 0 6px' }}>Top 3 Ataques</div>
          {(stats?.topTypes ?? []).map((t, i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:8, padding:'3px 0', borderBottom:'1px solid #161b22' }}>
              <span style={{ fontSize:10, color:'#6e7681', fontFamily:'monospace', width:16 }}>#{i+1}</span>
              <span style={{ flex:1, fontSize:10, color:'#8b949e' }}>{t.type}</span>
              <span style={{ fontSize:10, fontFamily:'monospace', color:'#ff2056' }}>{(t.count ?? 0).toLocaleString('pt-BR')}</span>
            </div>
          ))}
          <div style={{ fontSize:9, color:'#6e7681', textTransform:'uppercase', letterSpacing:1, margin:'10px 0 6px' }}>Top 3 IPs Origem</div>
          {(stats?.topIPs ?? []).map((ip, i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:8, padding:'3px 0', borderBottom:'1px solid #161b22' }}>
              <span style={{ fontSize:10, color:'#6e7681', fontFamily:'monospace', width:16 }}>#{i+1}</span>
              <span style={{ flex:1, fontSize:10, fontFamily:'monospace', color:'#8b949e' }}>{ip.ip}</span>
              <span style={{ fontSize:10, fontFamily:'monospace', color:'#ff6b00' }}>{ip.count ?? 0}</span>
            </div>
          ))}
          <div style={{ fontSize:9, color:'#6e7681', textTransform:'uppercase', letterSpacing:1, margin:'10px 0 6px' }}>Volume por hora</div>
          <div style={{ height:80 }}>
            <Line
              data={{
                labels: Array.from({length:12}, (_,i) => `${i}h`),
                datasets: [{ data: stats.hourlyData, borderColor:'#58a6ff', backgroundColor:'rgba(88,166,255,.06)', borderWidth:1.2, pointRadius:0, fill:true, tension:0.4 }],
              }}
              options={{
                responsive:true, maintainAspectRatio:false,
                plugins:{ legend:{ display:false } },
                scales:{
                  x:{ ticks:{ color:'#6e7681', font:{size:8} }, grid:{ color:'rgba(48,54,61,.4)' } },
                  y:{ ticks:{ color:'#6e7681', font:{size:8}, callback:(v:string|number)=>Number(v)>=1000?(Number(v)/1000).toFixed(0)+'k':String(v) }, grid:{ color:'rgba(48,54,61,.4)' } },
                },
              }}
            />
          </div>
        </>
      ) : null}
    </div>
  )
}

// ─── Layout style constants ───────────────────────────────────────────────────
const S = {
  mono:        { fontFamily:'monospace' } as React.CSSProperties,
  label:       { fontSize:9, color:'#6e7681', textTransform:'uppercase' as const, letterSpacing:1 },
  divider:     { width:1, height:24, background:'#30363d' } as React.CSSProperties,
  panelTitle:  { padding:'8px 12px', fontSize:11, fontWeight:'bold', color:'#8b949e', textTransform:'uppercase' as const, letterSpacing:1, borderBottom:'1px solid #21262d', flexShrink:0 } as React.CSSProperties,
  sectionTitle:{ padding:'8px 12px 4px', fontSize:10, color:'#6e7681', textTransform:'uppercase' as const, letterSpacing:1 } as React.CSSProperties,
}

// ─── Clock (self-contained, never causes parent re-render) ────────────────────
const Clock = React.memo(function Clock() {
  const [clock, setClock] = useState('')
  useEffect(() => {
    const ci = setInterval(
      () => setClock(new Date().toLocaleTimeString('pt-BR', { hour12:false }) + ' BRT'),
      1000
    )
    return () => clearInterval(ci)
  }, [])
  return <div style={{ ...S.mono, fontSize:12, color:'#8b949e' }}>{clock}</div>
})

// ─── MetricsPanel ─────────────────────────────────────────────────────────────
const MetricsPanel = React.memo(function MetricsPanel({
  dashStats24h, attackTypeItems, topOriginItems,
}: {
  stats?: Stats
  dashStats24h: { cntCrit:number; cntHigh:number; cntMedium:number; cntLow:number; cntHp:number } | null
  attackTypeItems: { name: string; pct: number; color: string }[]
  topOriginItems:  { name: string; code: string; count: number }[]
  loading?: boolean
}) {
  const fmt = (n: number) => n.toLocaleString('pt-BR')
  const d = dashStats24h
  return (
    <div style={{ background:'#0d1117', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <div style={S.panelTitle}>Métricas</div>
      <div className="panel-body" style={{ flex:1, overflowY:'auto', padding:'8px 0' }}>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:1 }}>
          {[
            { label:'Crítico',     val: !d ? '—' : fmt(d.cntCrit),   sev:'critical', sub:'últimas 24h' },
            { label:'Alto',        val: !d ? '—' : fmt(d.cntHigh),   sev:'high',     sub:'últimas 24h' },
            { label:'Médio',       val: !d ? '—' : fmt(d.cntMedium), sev:'medium',   sub:'últimas 24h' },
            { label:'Baixo',       val: !d ? '—' : fmt(d.cntLow),    sev:'low',      sub:'últimas 24h' },
            { label:'Honeypot SP', val: !d ? '—' : fmt(d.cntHp),     sev:'hp',       sub:'VPS São Paulo' },
          ].map(c => (
            <div key={c.label} style={{ background:'#161b22', padding:'10px 12px', borderLeft:`3px solid ${sevColor(c.sev)}` }}>
              <div style={S.label}>{c.label}</div>
              <div style={{ ...S.mono, fontSize:20, fontWeight:'bold', color:sevColor(c.sev), margin:'2px 0', textShadow:`0 0 8px ${SEV[c.sev]?.glow}` }}>{c.val}</div>
              <div style={{ fontSize:10, color:'#6e7681' }}>{c.sub}</div>
            </div>
          ))}
        </div>

        <div style={S.sectionTitle}>Tipos de Ataque</div>
        {attackTypeItems.map(a => (
          <div key={a.name} style={{ padding:'3px 12px' }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:2 }}>
              <span style={{ fontSize:11, color:'#8b949e' }}>{a.name}</span>
              <span style={{ ...S.mono, fontSize:11, color:a.color }}>{a.pct}%</span>
            </div>
            <div style={{ height:4, background:'#21262d', borderRadius:2 }}>
              <div style={{ height:4, width:`${a.pct}%`, background:a.color, borderRadius:2 }} />
            </div>
          </div>
        ))}

        <div style={S.sectionTitle}>Top Origens</div>
        {topOriginItems.map((o,i) => (
          <div key={o.code ?? o.name} style={{ display:'flex', alignItems:'center', gap:6, padding:'4px 10px' }}
            onMouseEnter={e=>(e.currentTarget.style.background='#161b22')}
            onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
            <div style={{ ...S.mono, fontSize:10, color:'#6e7681', width:16, flexShrink:0 }}>#{i+1}</div>
            {o.code && o.code.length === 2 && (
              <img
                src={`https://flagcdn.com/24x18/${o.code.toLowerCase()}.png`}
                alt={o.name} width={24} height={18}
                style={{ borderRadius:2, flexShrink:0 }}
              />
            )}
            <div style={{ flex:1, fontSize:11, color:'#8b949e', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{o.name}</div>
            <div style={{ ...S.mono, fontSize:11, color:'#ff2056', flexShrink:0 }}>{o.count.toLocaleString('pt-BR')}</div>
          </div>
        ))}
      </div>
    </div>
  )
})

// ─── MapSection ───────────────────────────────────────────────────────────────
const MapSection = React.memo(function MapSection({
  attacks, selectedState, activeRegion,
  onRegionChange, onStateClick,
  stateStats, stateLoading, stateNoData, onStateClose, tickItems,
}: {
  attacks:       Attack[]
  selectedState: SelectedState | null
  activeRegion:  string
  onRegionChange:(r: string) => void
  onStateClick:  (abbr: string, name: string) => void
  stateStats:    StateStats | null
  stateLoading:  boolean
  stateNoData:   boolean
  onStateClose:  () => void
  tickItems:     TickItem[]
}) {
  return (
    <div style={{ background:'#0d1117', display:'flex', flexDirection:'column', overflow:'hidden', position:'relative' }}>
      {/* Map header */}
      <div style={{ flexShrink:0, background:'#161b22', borderBottom:'1px solid #21262d' }}>
        <div style={{ padding:'5px 12px', display:'flex', alignItems:'center', gap:8, fontSize:11, color:'#8b949e', flexWrap:'wrap' }}>
          <span style={{ fontWeight:'bold', color:'#c9d1d9', flexShrink:0 }}>Mapa de Ataques — Brasil</span>
          <div style={{ marginLeft:'auto', display:'flex', gap:3, flexWrap:'wrap' }}>
            {(['Todas','Norte','Nordeste','Centro-Oeste','Sudeste','Sul'] as const).map(r => (
              <button key={r} onClick={() => onRegionChange(r)}
                style={{ padding:'2px 8px', fontSize:10, background: activeRegion===r?'rgba(88,166,255,.12)':'#21262d',
                  border:`1px solid ${activeRegion===r?'#58a6ff':'#30363d'}`,
                  color:activeRegion===r?'#58a6ff':'#6e7681', cursor:'pointer', borderRadius:3,
                  boxShadow: activeRegion===r?'0 0 6px rgba(88,166,255,.3)':'none' }}>
                {r==='Todas'?'Todas Regiões':r}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Leaflet map */}
      <MapContainer center={[-15,-50]} zoom={3} zoomControl style={{ flex:1 }} attributionControl={false}>
        <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" maxZoom={18} attribution="© OpenStreetMap, © CARTO" />
        <BrazilBorder />
        <StatesLayer selectedCode={selectedState?.code ?? null} activeRegion={activeRegion} onStateClick={onStateClick} />
        <MapController region={activeRegion} />
        <AttackLines attacks={attacks} />
      </MapContainer>

      {/* State detail panel overlay */}
      {selectedState && (
        <StateDetailPanel name={selectedState.name} stats={stateStats} loading={stateLoading} noData={stateNoData} onClose={onStateClose} />
      )}

      {/* Legend */}
      <div style={{ position:'absolute', bottom:36, left:10, zIndex:500, background:'rgba(13,17,23,.92)', border:'1px solid #30363d', padding:'6px 10px', borderRadius:4 }}>
        {Object.entries(SEV).filter(([k])=>k!=='hp').map(([k,s])=>(
          <div key={k} style={{ display:'flex', alignItems:'center', gap:6, padding:'1px 0' }}>
            <div style={{ width:8, height:8, borderRadius:'50%', background:s.color, boxShadow:`0 0 5px ${s.glow}` }} />
            <div style={{ fontSize:10, color:'#8b949e' }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Ticker */}
      <div style={{ height:28, background:'#161b22', borderTop:'1px solid #21262d', display:'flex', alignItems:'center', overflow:'hidden', flexShrink:0 }}>
        <div style={{ padding:'0 10px', fontSize:10, color:'#ff2056', borderRight:'1px solid #30363d', whiteSpace:'nowrap', flexShrink:0 }}>▶ LIVE</div>
        <div style={{ flex:1, overflow:'hidden' }}>
          <div style={{ display:'flex', alignItems:'center', height:28, whiteSpace:'nowrap', animation:'tickscroll 55s linear infinite' }}>
            {[...tickItems,...tickItems].map((t,i) => (
              <span key={i} style={{ padding:'0 16px', fontSize:10, fontFamily:'monospace',
                color: t.cls==='critical'?'#ff2056':t.cls==='high'?'#ff6b00':t.cls==='medium'?'#f5c400':'#00ff88' }}>
                {t.txt} &nbsp;|&nbsp;
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
})

// ─── IncidentFeed ─────────────────────────────────────────────────────────────

const IncidentFeed = React.memo(function IncidentFeed({
  incidents, loggedUser, flashingId, onSelectIncident,
}: {
  incidents:        SignalRIncident[]
  loggedUser:       string | null
  flashingId:       string | null
  onSelectIncident: (inc: SignalRIncident) => void
}) {
  // 30-second tick to refresh relative timestamps
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(id)
  }, [])

  const feedItems = useMemo(
    () => incidents.map(incidentToFeedItem),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [incidents, tick]
  )

  return (
    <div style={{ background:'#0d1117', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <div style={S.panelTitle}>Incidentes Recentes</div>
      <div className="panel-body" style={{ flex:1, overflowY:'auto' }}>
        {feedItems.map((inc) => {
          const isFlashing = flashingId !== null && inc.id === flashingId
          return (
            <div key={inc.id}
              style={{ padding:'7px 12px', borderBottom:'1px solid #161b22',
                cursor: loggedUser ? 'pointer' : 'default',
                transition: 'background 0.1s',
                borderLeft: isFlashing ? '3px solid #58a6ff' : '3px solid transparent',
                animation: isFlashing ? 'flashborder 2s ease-out forwards' : undefined }}
              onClick={() => loggedUser && onSelectIncident(inc.rawInc)}
              onMouseEnter={e=>(e.currentTarget.style.background='#161b22')}
              onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
              <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:3 }}>
                <span style={{ ...badgeStyle(inc.sev), padding:'1px 6px', fontSize:9, fontFamily:'monospace', borderRadius:3, fontWeight:'bold',
                  boxShadow:`0 0 6px ${SEV[inc.sev]?.glow??'transparent'}` }}>
                  {SEV[inc.sev]?.label ?? inc.sev.toUpperCase()}
                </span>
                <span style={{ fontSize:10, color:'#6e7681', marginLeft:'auto' }}>
                  {formatRelTime(inc.createdAt)}
                </span>
                {loggedUser && <span style={{ fontSize:9, color:'#30363d' }}>›</span>}
              </div>
              <div style={{ fontSize:11, fontWeight:'bold', color:'#c9d1d9' }}>{inc.type}</div>
              <div style={{ fontSize:10, fontFamily:'monospace', color:'#6e7681', marginTop:1 }}>{inc.detail}</div>
            </div>
          )
        })}
        {!loggedUser && feedItems.length > 0 && (
          <div style={{ padding:'8px 12px', fontSize:10, color:'#6e7681', textAlign:'center', borderTop:'1px solid #161b22' }}>
            Faça login para ver o detalhe dos incidentes
          </div>
        )}
      </div>
    </div>
  )
})

// ─── ThreatIntelFeed ──────────────────────────────────────────────────────────
const TI_SOURCE_LABEL: Record<string, string> = {
  OTX:          'OTX',
  AbuseIPDB:    'AbuseIPDB',
  FeodoTracker: 'Feodo',
  DShield:      'DShield',
  HoneyDB:      'HoneyDB',
  GreyNoise:    'GreyNoise',
}

const ThreatIntelFeed = React.memo(function ThreatIntelFeed({
  incidents,
}: {
  incidents: SignalRIncident[]
}) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(id)
  }, [])

  const items = useMemo(
    () => incidents.slice(0, 80).map(i => ({
      id:      String(i.id),
      sev:     SEV_MAP[i.severity] ?? 'low',
      src:     i.sourceIp,
      type:    i.attackType ?? 'Unknown',
      country: i.sourceCountry ?? '—',
      source:  TI_SOURCE_LABEL[i.dataSource ?? ''] ?? (i.dataSource ?? ''),
      time:    i.createdAt,
    })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [incidents, tick]
  )

  return (
    <div style={{ background:'#0d1117', display:'flex', flexDirection:'column', overflow:'hidden', borderTop:'1px solid #21262d' }}>
      <div style={{ ...S.panelTitle, background:'#0d1624' }}>
        Threat Intelligence
        <span style={{ marginLeft:'auto', fontSize:9, color:'#6e7681', fontWeight:'normal' }}>OTX · AbuseIPDB · Feodo · DShield · HoneyDB · GreyNoise</span>
      </div>
      <div className="panel-body" style={{ flex:1, overflowY:'auto' }}>
        {items.length === 0 && (
          <div style={{ padding:'16px 12px', fontSize:10, color:'#6e7681', textAlign:'center' }}>
            Aguardando dados de Threat Intelligence…
          </div>
        )}
        {items.map(item => (
          <div key={item.id}
            style={{ padding:'5px 12px', borderBottom:'1px solid #161b22', display:'flex', alignItems:'baseline', gap:6 }}>
            <span style={{ ...badgeStyle(item.sev), padding:'1px 5px', fontSize:9, fontFamily:'monospace', borderRadius:3, fontWeight:'bold', flexShrink:0 }}>
              {TI_SOURCE_LABEL[item.source] ?? item.source}
            </span>
            <span style={{ fontSize:10, fontFamily:'monospace', color:'#8b949e', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
              {item.src} — {item.type} — origem: {item.country}
            </span>
            <span style={{ fontSize:9, color:'#6e7681', flexShrink:0 }}>{formatRelTime(item.time)}</span>
          </div>
        ))}
      </div>
    </div>
  )
})

// ─── Dashboard ────────────────────────────────────────────────────────────────
export default function Dashboard() {
  // ── Single source of truth ────────────────────────────────────────────────
  const [incidents,  setIncidents]  = useState<SignalRIncident[]>([])
  const [loading,    setLoading]    = useState(true)

  // ── UI state ──────────────────────────────────────────────────────────────
  const [modalOpen,    setModalOpen]    = useState(false)
  const [loginUser,    setLoginUser]    = useState('')
  const [loginPass,    setLoginPass]    = useState('')
  const [loginMsg,     setLoginMsg]     = useState('')
  const [loggedUser,   setLoggedUser]   = useState<string|null>(null)
  const [activeTab,    setActiveTab]    = useState('Ao Vivo')
  const [activeRegion, setActiveRegion] = useState('Todas')
  const [selectedState,    setSelectedState]    = useState<SelectedState|null>(null)
  const [stateStats,       setStateStats]       = useState<StateStats|null>(null)
  const [stateLoading,     setStateLoading]     = useState(false)
  const [stateNoData,      setStateNoData]      = useState(false)
  const [selectedIncident, setSelectedIncident] = useState<SignalRIncident|null>(null)
  const [atkMin,           setAtkMin]           = useState(0)
  const attackTimestamps = useRef<number[]>([])

  // ── Real-time animation state ─────────────────────────────────────────────
  const [flashingId,   setFlashingId]   = useState<string|null>(null)

  // ── 24h dashboard stats (refreshed every 5 min, retry 30s on failure) ──────
  const [dashStats24h, setDashStats24h] = useState<{ cntCrit:number; cntHigh:number; cntMedium:number; cntLow:number; cntHp:number; totalHoje:number } | null>(null)
  useEffect(() => {
    let retryId: ReturnType<typeof setTimeout> | null = null
    let intervalId: ReturnType<typeof setInterval> | null = null

    const fetchDash = () =>
      fetch(`${API_BASE}/api/dashboard/stats?hours=24`)
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(d => {
          console.log('[Metrics] stats recebido:', d)
          const sev = d.bySeverity ?? {}
          const mapped = {
            cntCrit:   sev.critical  ?? sev.Critical  ?? 0,
            cntHigh:   sev.high      ?? sev.High      ?? 0,
            cntMedium: sev.medium    ?? sev.Medium    ?? 0,
            cntLow:    sev.low       ?? sev.Low       ?? 0,
            cntHp:     d.total       ?? 0,
            totalHoje: d.totalHoje   ?? 0,
          }
          console.log('[Metrics] mapeado:', mapped)
          setDashStats24h(mapped)
          // Sucesso: garante intervalo de 5 min rodando
          if (!intervalId) intervalId = setInterval(fetchDash, 5 * 60_000)
        })
        .catch(() => {
          console.warn('[Metrics] falha ao buscar stats, retry em 30s')
          retryId = setTimeout(fetchDash, 30_000)
        })

    fetchDash()
    return () => {
      if (intervalId) clearInterval(intervalId)
      if (retryId)   clearTimeout(retryId)
    }
  }, [])

  const { incidents: signalrIncidents, connectionStatus } = useSignalR()

  // ── Ataques/min — janela deslizante de 60s ────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      const oneMinAgo = Date.now() - 60_000
      attackTimestamps.current = attackTimestamps.current.filter(t => t > oneMinAgo)
      setAtkMin(attackTimestamps.current.length)
    }, 1000)
    return () => clearInterval(id)
  }, [])

  // ── Init from API (once) ──────────────────────────────────────────────────
  useEffect(() => {
    fetch(`${API_BASE}/api/incidents?limit=100`)
      .then(r => r.ok ? r.json() as Promise<SignalRIncident[]> : [])
      .then(data => { setIncidents(data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  // ── Merge incoming SignalR incidents ──────────────────────────────────────
  const prevFirstIdRef = useRef<string|null>(null)
  useEffect(() => {
    if (signalrIncidents.length === 0) return
    const newest = signalrIncidents[0]
    const newId  = String(newest.id)
    if (newId === prevFirstIdRef.current) return
    prevFirstIdRef.current = newId

    setIncidents(prev =>
      prev.some(i => String(i.id) === newId) ? prev : [newest, ...prev].slice(0, 100)
    )

    // Registra timestamp para o contador ataques/min (apenas honeypot)
    if (isHoneypot(newest.dataSource)) {
      attackTimestamps.current.push(Date.now())
    }

    // Feed flash
    setFlashingId(newId)
    const tf = setTimeout(() => setFlashingId(null), 2000)

    return () => { clearTimeout(tf) }
  }, [signalrIncidents])


  // ── Split by source ───────────────────────────────────────────────────────
  const honeypotIncidents  = useMemo(() => incidents.filter(i => isHoneypot(i.dataSource)),   [incidents])
  const threatIntelIncidents = useMemo(() => incidents.filter(i => isThreatIntel(i.dataSource)), [incidents])

  // ── Derived stats via useMemo (honeypot only) ─────────────────────────────
  const stats = useMemo((): Stats => {
    const totalHoje = dashStats24h?.totalHoje ?? honeypotIncidents.length
    return {
      atkTotal:  totalHoje,
      atkMin:    atkMin,
      atkIps:       new Set(honeypotIncidents.map(i => i.sourceIp)).size,
      atkCountries: new Set(honeypotIncidents.map(i => i.sourceCountry).filter(Boolean)).size,
      crits:     honeypotIncidents.filter(i => i.severity === 'Critical').length,
      cntCrit:   honeypotIncidents.filter(i => i.severity === 'Critical').length,
      cntHigh:   honeypotIncidents.filter(i => i.severity === 'High').length,
      cntMedium: honeypotIncidents.filter(i => i.severity === 'Medium').length,
      cntLow:    honeypotIncidents.filter(i => i.severity === 'Low').length,
      cntHp:     honeypotIncidents.length,
    }
  }, [honeypotIncidents, dashStats24h, atkMin])

  const attackTypeItems = useMemo(() => {
    if (honeypotIncidents.length === 0) return ATTACK_TYPES
    const counts = new Map<string, number>()
    for (const i of honeypotIncidents) {
      const t = resolveAttackType(i)
      counts.set(t, (counts.get(t) ?? 0) + 1)
    }
    const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 7)
    const total  = sorted.reduce((s, [, c]) => s + c, 0) || 1
    return sorted.map(([name, count], idx) => ({
      name, pct: Math.round(count / total * 100), color: ATTACK_TYPE_COLORS[idx % ATTACK_TYPE_COLORS.length],
    }))
  }, [honeypotIncidents])

  const topOriginItems = useMemo(() => {
    if (honeypotIncidents.length === 0) return TOP_ORIGINS
    const counts = new Map<string, number>()
    for (const i of honeypotIncidents)
      if (i.sourceCountry) counts.set(i.sourceCountry, (counts.get(i.sourceCountry) ?? 0) + 1)
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([code, count]) => ({ name: countryDisplayName(code), code, count }))
  }, [honeypotIncidents])

  const tickItems = useMemo<TickItem[]>(() =>
    honeypotIncidents.length > 0
      ? honeypotIncidents.slice(0, 14).map(i => ({
          cls: SEV_MAP[i.severity] ?? 'low',
          txt: `[${(i.severity ?? 'INFO').toUpperCase()}] ${resolveAttackType(i)} ${i.sourceIp}${i.sourceCity ? ` → ${i.sourceCity}` : i.sourceCountry ? ` (${i.sourceCountry})` : ''} → São Paulo/SP`,
        }))
      : TICKS
  , [honeypotIncidents])

  const allGeoIncidents = useMemo(() => {
    const hasData = incidents.length > 0
    if (!hasData) return loading ? [] : null  // null = use ATTACKS fallback
    // Map shows ONLY honeypot incidents — Threat Intel goes to the side panel only
    return incidents.filter(i =>
      isHoneypot(i.dataSource) &&
      i.latitude && i.longitude && i.latitude !== 0 && i.longitude !== 0
    )
  }, [incidents, loading])

  const liveAttacks = useMemo(() => {
    if (allGeoIncidents === null) return ATTACKS
    return allGeoIncidents.map(incidentToAttack)
  }, [allGeoIncidents])

  const visibleAttacks = useMemo(() =>
    activeRegion === 'Todas'
      ? liveAttacks
      : liveAttacks.filter(a => STATE_REGION[a.state] === activeRegion)
  , [liveAttacks, activeRegion])

  const fmt = (n: number) => n.toLocaleString('pt-BR')

  const doLogin = useCallback(() => {
    if (!loginUser || !loginPass) { setLoginMsg('Preencha todos os campos.'); return }
    const u = USERS[loginUser]
    if (u && u.pass === loginPass) {
      setLoggedUser(`${loginUser} (${u.role})`)
      setModalOpen(false); setLoginUser(''); setLoginPass(''); setLoginMsg('')
    } else { setLoginMsg('Usuário ou senha incorretos.'); setLoginPass('') }
  }, [loginUser, loginPass])

  const handleStateClick = useCallback((abbr: string, name: string) => {
    console.log('[StatePanel] estado clicado:', abbr)
    setSelectedState({ code: abbr, name })
    setStateStats(null)
    setStateNoData(false)
    if (abbr !== 'SP') {
      setStateLoading(false)
      setStateNoData(true)
      return
    }
    setStateLoading(true)
    fetchStateStats(abbr, name).then(s => { setStateStats(s); setStateLoading(false) })
  }, [])

  const handleStateClose = useCallback(() => { setSelectedState(null); setStateStats(null); setStateNoData(false) }, [])
  const handleSelectIncident = useCallback((inc: SignalRIncident) => setSelectedIncident(inc), [])

  return (
    <div style={{ height:'100vh', display:'flex', flexDirection:'column', background:'#0d1117', color:'#c9d1d9', overflow:'hidden', fontFamily:'Arial,sans-serif', fontSize:13 }}>

      {/* ── Topbar ── */}
      <div style={{ height:48, background:'#161b22', borderBottom:'1px solid #30363d', display:'flex', alignItems:'center', padding:'0 14px', gap:16, flexShrink:0 }}>
        <div style={{ fontSize:16, fontWeight:'bold', color:'#00ff88', letterSpacing:1 }}>
          Cybex<span style={{ color:'#00cc66' }}>Node</span> <span style={{ color:'#8b949e', fontWeight:400, fontSize:12 }}>BR</span>
        </div>
        <div style={S.divider} />
        <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'#8b949e' }}>
          <div style={{ width:7, height:7, borderRadius:'50%', background:'#3fb950', animation:'blink 1.5s infinite' }} />
          Monitoramento em tempo real
        </div>
        <div style={S.divider} />
        <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'#8b949e' }}>
          <div style={{
            width:7, height:7, borderRadius:'50%',
            background:   connectionStatus==='connected'?'#3fb950':connectionStatus!=='disconnected'?'#f5c400':'#ff2056',
            boxShadow:    connectionStatus==='connected'?'0 0 5px #3fb950':connectionStatus!=='disconnected'?'0 0 5px #f5c400':'0 0 5px #ff2056',
            animation:    connectionStatus!=='connected'?'blink 1.5s infinite':'none',
          }} />
          SignalR {connectionStatus==='connected'?'online':connectionStatus==='reconnecting'?'reconectando':connectionStatus==='connecting'?'conectando':'offline'}
        </div>
        <div style={S.divider} />
        <div style={{ display:'flex', gap:20 }}>
          {[
            { label:'Ataques/min', val:String(stats.atkMin),  red:true  },
            { label:'Total hoje',  val:fmt(stats.atkTotal),   red:false },
            { label:'IPs únicos',  val:fmt(stats.atkIps),     red:false },
            { label:'Países',      val:fmt(stats.atkCountries ?? 0), green:true},
            { label:'Críticos',    val:String(stats.crits),   red:true  },
          ].map(s => (
            <div key={s.label} style={{ display:'flex', flexDirection:'column' }}>
              <div style={S.label}>{s.label}</div>
              <div style={{ ...S.mono, fontSize:14, fontWeight:'bold',
                color:(s as {red?:boolean}).red?'#ff2056':(s as {green?:boolean}).green?'#00ff88':'#58a6ff' }}>
                {s.val}
              </div>
            </div>
          ))}
        </div>
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:10 }}>
          <Clock />
          <div style={S.divider} />
          {['Ao Vivo','Histórico','Relatório'].map(t => (
            <button key={t} onClick={()=>setActiveTab(t)}
              style={{ padding:'4px 12px', background:'#21262d', border:`1px solid ${activeTab===t?'#58a6ff':'#30363d'}`,
                color:activeTab===t?'#58a6ff':'#c9d1d9', fontSize:12, cursor:'pointer', borderRadius:4 }}>
              {t}
            </button>
          ))}
          <div style={S.divider} />
          <button onClick={()=>loggedUser?setLoggedUser(null):setModalOpen(true)}
            style={{ padding:'4px 12px', background:loggedUser?'rgba(0,255,136,.08)':'transparent',
              border:`1px solid ${loggedUser?'#00ff88':'#ff2056'}`,
              color:loggedUser?'#00ff88':'#ff2056', fontSize:12, cursor:'pointer', borderRadius:4 }}>
            {loggedUser ?? 'Login'}
          </button>
        </div>
      </div>

      {/* ── Login Modal ── */}
      {modalOpen && (
        <div onClick={e=>{if(e.target===e.currentTarget)setModalOpen(false)}}
          style={{ position:'fixed', inset:0, zIndex:9999, background:'rgba(0,0,0,.75)', display:'flex', alignItems:'center', justifyContent:'center' }}>
          <div style={{ background:'#161b22', border:'1px solid #30363d', borderRadius:6, padding:'28px 24px', width:320, position:'relative' }}>
            <button onClick={()=>setModalOpen(false)} style={{ position:'absolute', top:10, right:12, background:'none', border:'none', color:'#6e7681', fontSize:16, cursor:'pointer' }}>✕</button>
            <div style={{ fontSize:15, color:'#00ff88', fontWeight:'bold', textAlign:'center', marginBottom:4 }}>CybexNode BR</div>
            <div style={{ fontSize:10, color:'#6e7681', textAlign:'center', marginBottom:20, textTransform:'uppercase', letterSpacing:1 }}>Acesso ao sistema</div>
            {['Usuário','Senha'].map((lbl,i)=>(
              <div key={lbl}>
                <div style={{ fontSize:11, color:'#6e7681', marginBottom:4 }}>{lbl}</div>
                <input type={i===1?'password':'text'} value={i===0?loginUser:loginPass}
                  onChange={e=>i===0?setLoginUser(e.target.value):setLoginPass(e.target.value)}
                  onKeyDown={e=>e.key==='Enter'&&doLogin()}
                  placeholder={i===0?'email@exemplo.com':'••••••••'}
                  style={{ width:'100%', padding:'8px 10px', background:'#0d1117', border:'1px solid #30363d',
                    color:'#c9d1d9', fontSize:13, borderRadius:4, marginBottom:14, outline:'none', display:'block' }} />
              </div>
            ))}
            <button onClick={doLogin} style={{ width:'100%', padding:9, background:'#1f6feb', border:'none', color:'#fff', fontSize:13, fontWeight:'bold', borderRadius:4, cursor:'pointer' }}>Entrar</button>
            {loginMsg&&<div style={{ fontSize:11, color:'#ff2056', textAlign:'center', marginTop:10 }}>{loginMsg}</div>}
            <div style={{ marginTop:14, paddingTop:12, borderTop:'1px solid #21262d', fontSize:10, color:'#6e7681', textAlign:'center', lineHeight:1.9, fontFamily:'monospace' }}>
              <b style={{color:'#8b949e'}}>admin</b> / admin123 — Administrador<br/>
              <b style={{color:'#8b949e'}}>analista</b> / analista123 — Analista
            </div>
          </div>
        </div>
      )}

      {/* ── Main grid ── */}
      <div style={{ flex:1, display:'grid', gridTemplateColumns:'240px 1fr 270px', overflow:'hidden', gap:1, background:'#30363d' }}>
        <MetricsPanel
          stats={stats}
          dashStats24h={dashStats24h}
          attackTypeItems={attackTypeItems}
          topOriginItems={topOriginItems}
          loading={loading}
        />
        <MapSection
          attacks={visibleAttacks}
          selectedState={selectedState}
          activeRegion={activeRegion}
          onRegionChange={setActiveRegion}
          onStateClick={handleStateClick}
          stateStats={stateStats}
          stateLoading={stateLoading}
          stateNoData={stateNoData}
          onStateClose={handleStateClose}
          tickItems={tickItems}
        />
        {/* Right column: Honeypot feed (60%) + Threat Intel feed (40%) */}
        <div style={{ display:'flex', flexDirection:'column', overflow:'hidden', gap:1 }}>
          <div style={{ flex:'0 0 60%', minHeight:0, display:'flex', flexDirection:'column', overflow:'hidden' }}>
            <IncidentFeed
              incidents={honeypotIncidents}
              loggedUser={loggedUser}
              flashingId={flashingId}
              onSelectIncident={handleSelectIncident}
            />
          </div>
          <div style={{ flex:'0 0 40%', minHeight:0, display:'flex', flexDirection:'column', overflow:'hidden' }}>
            <ThreatIntelFeed incidents={threatIntelIncidents} />
          </div>
        </div>
      </div>

      {/* ── Incident Detail Drawer ── */}
      {selectedIncident && loggedUser && (
        <IncidentDrawer incident={selectedIncident} onClose={() => setSelectedIncident(null)} />
      )}
    </div>
  )
}
