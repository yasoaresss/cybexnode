import { NextResponse } from 'next/server'

const IBGE_URL = 'https://servicodados.ibge.gov.br/api/v3/malhas/paises/BR?formato=application/vnd.geo+json&qualidade=intermediario'

export async function GET() {
  try {
    const res = await fetch(IBGE_URL, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      console.log(`[CybexNode] /api/geojson/border — ${Array.isArray(data?.features) ? data.features.length : '?'} feature(s)`)
      return NextResponse.json(data)
    }
  } catch (err) {
    console.warn('[CybexNode] /api/geojson/border falhou no IBGE', err)
  }
  return NextResponse.json({ error: 'GeoJSON unavailable' }, { status: 502 })
}
