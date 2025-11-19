import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { Card, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Play, TrendingUp, Shield, Target, Zap } from 'lucide-react';
import { useMemo, useState } from 'react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/defense-simulation')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const [isRunning, setIsRunning] = useState(false);

  const timeline = useMemo(
    () => [
      { time: 'T+0s', attacker: 0, defender: 100, event: 'Initial State' },
      { time: 'T+5s', attacker: 15, defender: 95, event: 'Probe Detected' },
      { time: 'T+10s', attacker: 30, defender: 85, event: 'First Breach Attempt' },
      { time: 'T+15s', attacker: 45, defender: 75, event: 'Defense Activated' },
      { time: 'T+20s', attacker: 60, defender: 70, event: 'Countermeasure Deployed' },
      { time: 'T+25s', attacker: 55, defender: 80, event: 'Threat Mitigated' },
    ],
    []
  );

  const defenseSuggestions = useMemo(
    () => [
      {
        id: '1',
        name: 'Enable Rate Limiting',
        priority: 'high' as const,
        effectiveness: 85,
        description: 'Limit request rate to prevent flooding attacks',
      },
      {
        id: '2',
        name: 'Deploy WAF Rules',
        priority: 'high' as const,
        effectiveness: 78,
        description: 'Web Application Firewall rules to filter malicious traffic',
      },
      {
        id: '3',
        name: 'Isolate Affected Nodes',
        priority: 'medium' as const,
        effectiveness: 65,
        description: 'Network isolation to contain the threat',
      },
      {
        id: '4',
        name: 'Update Firewall Rules',
        priority: 'medium' as const,
        effectiveness: 58,
        description: 'Restrict network access to vulnerable services',
      },
      {
        id: '5',
        name: 'Increase Monitoring',
        priority: 'low' as const,
        effectiveness: 42,
        description: 'Enhanced logging and alerting for early detection',
      },
    ],
    []
  );

  const probabilityData = useMemo(
    () => [
      { label: 'Success', value: 72, color: 'rgb(93, 229, 255)' },
      { label: 'Partial', value: 18, color: 'rgb(192, 132, 252)' },
      { label: 'Failure', value: 10, color: 'rgb(255, 107, 107)' },
    ],
    []
  );

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Defense Simulator">
      <div className="p-6 flex-1 min-h-0 flex flex-col gap-6 overflow-auto">
        {/* Timeline Animation Card */}
        <Card size="large" className="flex flex-col">
          <CardHeader
            title="Timeline Animation"
            icon={<TrendingUp className="text-cyan-400" size={20} />}
          />
          <div className="flex-1 overflow-y-auto space-y-4">
            {timeline.map((step, idx) => (
              <div key={idx} className="relative">
                <div className="flex items-center gap-4">
                  <div className="text-xs font-mono text-gray-400 w-16">{step.time}</div>
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-red-400 w-20">Attacker</span>
                      <div className="flex-1 bg-gray-800 rounded-full h-3">
                        <div
                          className="bg-red-500 h-3 rounded-full transition-all duration-500"
                          style={{
                            width: `${step.attacker}%`,
                            boxShadow: '0 0 8px rgba(239, 68, 68, 0.6)',
                          }}
                        />
                      </div>
                      <span className="text-xs text-red-400 font-mono w-12 text-right">
                        {step.attacker}%
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-cyan-400 w-20">Defender</span>
                      <div className="flex-1 bg-gray-800 rounded-full h-3">
                        <div
                          className="bg-cyan-500 h-3 rounded-full transition-all duration-500"
                          style={{
                            width: `${step.defender}%`,
                            boxShadow: '0 0 8px rgba(93, 229, 255, 0.6)',
                          }}
                        />
                      </div>
                      <span className="text-xs text-cyan-400 font-mono w-12 text-right">
                        {step.defender}%
                      </span>
                    </div>
                    <div className="text-xs text-gray-500 mt-1">{step.event}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Probability Chart Card */}
          <Card size="medium" className="flex flex-col">
            <CardHeader
              title="Probability"
              icon={<Target className="text-purple-400" size={20} />}
            />
            <div className="flex-1 flex flex-col justify-center space-y-4">
              {probabilityData.map((item, idx) => (
                <div key={idx} className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-300">{item.label}</span>
                    <span className="font-mono" style={{ color: item.color }}>
                      {item.value}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-3">
                    <div
                      className="h-3 rounded-full transition-all duration-500"
                      style={{
                        width: `${item.value}%`,
                        backgroundColor: item.color,
                        boxShadow: `0 0 10px ${item.color}80`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Defense Suggestions Card */}
          <Card size="medium" className="flex flex-col">
            <CardHeader
              title="Defense Suggestions"
              icon={<Shield className="text-cyan-400" size={20} />}
            />
            <div className="flex-1 overflow-y-auto space-y-3">
              {defenseSuggestions.map((suggestion) => (
                <div
                  key={suggestion.id}
                  className="border border-cyan-500/30 bg-cyan-500/10 p-4 rounded"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <div className="text-sm text-gray-200 font-semibold">{suggestion.name}</div>
                      <div className="text-xs text-gray-400 mt-1">{suggestion.description}</div>
                    </div>
                    <span
                      className={`text-xs px-2 py-1 rounded ${
                        suggestion.priority === 'high'
                          ? 'bg-red-500/20 text-red-300'
                          : suggestion.priority === 'medium'
                            ? 'bg-yellow-500/20 text-yellow-300'
                            : 'bg-green-500/20 text-green-300'
                      }`}
                    >
                      {suggestion.priority}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mt-2">
                    <div className="text-xs text-gray-400">
                      Effectiveness: <span className="text-cyan-400">{suggestion.effectiveness}%</span>
                    </div>
                    <div className="w-24 bg-gray-800 rounded-full h-2">
                      <div
                        className="bg-cyan-400 h-2 rounded-full"
                        style={{ width: `${suggestion.effectiveness}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Run Simulation Button */}
        <div className="flex justify-center">
          <Button
            onClick={() => setIsRunning(!isRunning)}
            icon={<Play size={16} />}
            className="border-red-500 text-red-400 hover:bg-red-500/10 glow-accent px-8"
            style={{
              boxShadow: '0 0 20px rgba(239, 68, 68, 0.6)',
            }}
          >
            {isRunning ? 'Stop Simulation' : 'Run Simulation'}
          </Button>
        </div>
      </div>
    </TelemetryLayout>
  );
}
