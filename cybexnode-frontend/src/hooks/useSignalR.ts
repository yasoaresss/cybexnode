import { useEffect, useRef, useState } from 'react'
import * as signalR from '@microsoft/signalr'
import type { Incident } from '@/types/incident'

const HUB_URL    = process.env.NEXT_PUBLIC_SIGNALR_URL ?? 'http://localhost:5277/hubs/incidents'
const MAX_ITEMS  = 50
const BACKOFF_MS = [1000, 2000, 4000, 8000]

export type ConnectionStatus = 'connecting' | 'connected' | 'reconnecting' | 'disconnected'

export function useSignalR() {
  const [incidents,        setIncidents]        = useState<Incident[]>([])
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connecting')

  const stoppedRef    = useRef(false)
  const retryIndexRef = useRef(0)
  const timerRef      = useRef<ReturnType<typeof setTimeout> | null>(null)
  const connRef       = useRef<signalR.HubConnection | null>(null)

  useEffect(() => {
    // useEffect only runs in the browser — guard is redundant but explicit
    if (typeof window === 'undefined') return

    stoppedRef.current = false

    function scheduleRetry() {
      const delay = BACKOFF_MS[Math.min(retryIndexRef.current, BACKOFF_MS.length - 1)]
      retryIndexRef.current = Math.min(retryIndexRef.current + 1, BACKOFF_MS.length - 1)
      timerRef.current = setTimeout(connect, delay)
    }

    async function connect() {
      if (stoppedRef.current) return

      const connection = new signalR.HubConnectionBuilder()
        .withUrl(HUB_URL, {
          transport: signalR.HttpTransportType.ServerSentEvents |
                     signalR.HttpTransportType.LongPolling,
        })
        .configureLogging(signalR.LogLevel.None)
        .build()

      connRef.current = connection

      connection.onclose(() => {
        if (stoppedRef.current) return
        setConnectionStatus('reconnecting')
        scheduleRetry()
      })

      connection.on('IncidentCreated', (incident: Incident) => {
        if (stoppedRef.current) return
        setIncidents(prev => [incident, ...prev].slice(0, MAX_ITEMS))
      })

      try {
        setConnectionStatus('connecting')
        await connection.start()
        if (stoppedRef.current) { connection.stop(); return }
        setConnectionStatus('connected')
        retryIndexRef.current = 0
      } catch {
        if (stoppedRef.current) return
        setConnectionStatus('disconnected')
        scheduleRetry()
      }
    }

    connect()

    return () => {
      stoppedRef.current = true
      if (timerRef.current) clearTimeout(timerRef.current)
      connRef.current?.stop()
      connRef.current = null
    }
  }, [])

  return {
    incidents,
    isConnected: connectionStatus === 'connected',
    connectionStatus,
  }
}
