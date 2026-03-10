# 🛡️ CybexNode

**CybexNode** é uma plataforma de **monitoramento de ameaças cibernéticas em tempo real focada no Brasil**.  
Ela agrega dados de múltiplas fontes de **Threat Intelligence** e apresenta tudo em um **dashboard interativo com mapa, gráficos e feed ao vivo**.

# 📊 Arquitetura do Projeto

CybexNode.Api → ASP.NET Core Web API + SignalR
CybexNode.Worker → Background Workers de Threat Intelligence
cybexnode-frontend → Dashboard Next.js (React + Leaflet + Chart.js)

# 🚀 Funcionalidades

- 🗺️ **Mapa interativo do Brasil** com marcadores de ataques em tempo real por severidade  
- ⚡ **Feed ao vivo** via SignalR — incidentes chegam sem refresh  
- 📈 **Estatísticas em tempo real**
  - ataques por minuto
  - total de IPs únicos
  - países de origem
  - distribuição por severidade  
- 📍 **Drawer por estado** com detalhes:
  - tipos de ataque
  - top IPs
  - atividade por hora  
- 🧬 **Integração com CVEs** via **CISA KEV**  
- 🔑 **Autenticação por API Key** (`X-Api-Key`) para sensores honeypot  

# 🧠 Fontes de Threat Intelligence

| Worker | Fonte | Intervalo |
|------|------|------|
| `AbuseIpDbWorker` | AbuseIPDB (IPs maliciosos reportados) | 24h |
| `CisaWorker` | CISA KEV (vulnerabilidades exploradas ativamente) | 24h |
| `DShieldWorker` | DShield / SANS (top IPs atacantes) | 1h |
| `FeodoWorker` | Feodo Tracker (C2 botnet) | 6h |
| `GreyNoiseWorker` | GreyNoise (internet scanners / noise) | 6h |
| `HoneyDbWorker` | HoneyDB (atividade de honeypots) | 12h |
| `OtxWorker` | AlienVault OTX (threat intelligence) | 6h |

# 🏗️ Stack Tecnológica

## Backend

- **ASP.NET Core 8 (C#)**
- **Entity Framework Core**
- **SQL Server**
- **SignalR** (tempo real)
- **MaxMind GeoIP2** (geolocalização de IP)

## Frontend

- **Next.js 14**
- **TypeScript**
- **React-Leaflet** (mapa interativo)
- **Chart.js** (gráficos)
- **TailwindCSS**

# ☁️ Infraestrutura

| Serviço | Função |
|------|------|
| **Azure App Service** | API Backend |
| **Azure WebJob** | Workers de coleta de inteligência |
| **Azure Static Web Apps** | Frontend |
| **Azure SQL Database** | Banco de dados |

# 🔌 Integração com Sensores

Sensores ou honeypots podem enviar eventos usando:

POST /api/events

Header obrigatório:
X-Api-Key: SUA_API_KEY

# 📡 Tempo Real

A plataforma usa **SignalR** para enviar novos incidentes ao dashboard instantaneamente.

Eventos recebidos incluem:

- Novo ataque detectado
- Atualização de estatísticas
- Novos IPs maliciosos
