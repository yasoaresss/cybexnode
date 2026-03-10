import { NextResponse } from 'next/server'

const IBGE_URL     = 'https://servicodados.ibge.gov.br/api/v3/malhas/paises/BR?formato=application/vnd.geo+json&qualidade=intermediario&divisao=estadual'
const FALLBACK_URL = 'https://raw.githubusercontent.com/codeforamerica/click_that_hood/master/public/data/brazil-states.geojson'

export async function GET() {
  for (const url of [IBGE_URL, FALLBACK_URL]) {
    try {
      const res = await fetch(url, { cache: 'no-store' })
      if (!res.ok) continue
      const data = await res.json()
      console.log(`[CybexNode] /api/geojson/states — ${Array.isArray(data?.features) ? data.features.length : '?'} feature(s) de ${url}`)
      return NextResponse.json(data)
    } catch (err) {
      console.warn(`[CybexNode] /api/geojson/states falhou em ${url}`, err)
    }
  }
  return NextResponse.json({ error: 'GeoJSON unavailable' }, { status: 502 })
}
