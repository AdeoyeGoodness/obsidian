export type LabelScore = {
  id: string
  score?: number | null
}

export type ThreatPrediction = {
  cwe: LabelScore[]
  capec: LabelScore[]
}

const API_URL =
  import.meta.env.VITE_THREAT_MODEL_API?.trim() || 'http://localhost:8001/predict'

export async function fetchThreatPrediction(description: string): Promise<ThreatPrediction> {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ description }),
  })

  if (!response.ok) {
    throw new Error(`THREAT_MODEL_API failed: ${response.status}`)
  }

  return (await response.json()) as ThreatPrediction
}

