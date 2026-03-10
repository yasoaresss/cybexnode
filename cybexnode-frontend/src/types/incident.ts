export interface Incident {
  id: string
  sourceIp: string
  destinationIp: string
  sourcePort: number
  destinationPort: number
  protocol: string
  attackType: string
  severity: string        // 'Critical' | 'High' | 'Medium' | 'Low'
  sourceCountry: string
  sourceCity: string
  latitude: number
  longitude: number
  dataSource: string      // 'OTX' | 'AbuseIPDB' | 'HoneypotSP' | etc
  status: string
  createdAt: string
}
