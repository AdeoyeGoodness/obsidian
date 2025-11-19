import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { Card, CardHeader, StatCard } from '@/components/ui/card';
import { Activity, AlertTriangle, TrendingUp, Shield, Clock, Zap } from 'lucide-react';
import { useMemo } from 'react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();

  const systemStatus = useMemo(() => {
    return Math.random() > 0.3 ? 'Secure' : 'Threat Detected';
  }, []);

  const networkHealth = useMemo(() => 87, []);
  const activeThreats = useMemo(
    () => [
      { id: '1', name: 'ICEBREAKER 7.2', severity: 'high', status: 'active' },
      { id: '2', name: 'CAPEC-163', severity: 'medium', status: 'monitoring' },
      { id: '3', name: 'CAPEC-94', severity: 'low', status: 'resolved' },
    ],
    []
  );

  const recentAlerts = useMemo(
    () => [
      { id: '1', time: '2m ago', type: 'Anomaly Detected', severity: 'high' },
      { id: '2', time: '15m ago', type: 'Pattern Match', severity: 'medium' },
      { id: '3', time: '1h ago', type: 'System Update', severity: 'low' },
    ],
    []
  );

  const stats = useMemo(
    () => ({
      totalCVEs: 42,
      highRiskNodes: 8,
      activeThreats: 3,
      mitigated: 15,
    }),
    []
  );

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Dashboard">
      <div className="p-6 flex-1 min-h-0 flex flex-col gap-6 overflow-auto" style={{ padding: '24px', gap: '24px' }}>
        {/* System Status - Large Card */}
        <Card size="large" glow pulse={systemStatus === 'Threat Detected'}>
          <CardHeader
            title="System Status"
            icon={<Activity size={20} />}
            action={
              <div className="flex items-center gap-2">
                <div
                  className={`h-3 w-3 rounded-full ${
                    systemStatus === 'Secure'
                      ? 'bg-green-500 animate-pulse'
                      : 'bg-yellow-500 animate-pulse'
                  }`}
                  style={{
                    boxShadow:
                      systemStatus === 'Secure'
                        ? '0 0 10px rgba(34, 197, 94, 0.8)'
                        : '0 0 10px rgba(234, 179, 8, 0.8)',
                  }}
                />
                <span className="text-sm uppercase tracking-wider text-gray-300">{systemStatus}</span>
              </div>
            }
          />
          <div className="flex items-center gap-8">
            <div className="relative w-40 h-40">
              <svg className="transform -rotate-90 w-40 h-40">
                <circle
                  cx="80"
                  cy="80"
                  r="70"
                  stroke="rgba(93, 229, 255, 0.2)"
                  strokeWidth="10"
                  fill="none"
                />
                <circle
                  cx="80"
                  cy="80"
                  r="70"
                  stroke="rgb(93, 229, 255)"
                  strokeWidth="10"
                  fill="none"
                  strokeDasharray={`${(networkHealth / 100) * 439.82} 439.82`}
                  style={{
                    filter: 'drop-shadow(0 0 8px rgba(93, 229, 255, 0.6))',
                    transition: 'stroke-dasharray 0.5s ease',
                  }}
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-3xl font-bold text-cyan-400">{networkHealth}%</span>
              </div>
            </div>
            <div className="flex-1 grid grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Uptime</p>
                <p className="text-xl font-mono text-cyan-400">99.97%</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Latency</p>
                <p className="text-xl font-mono text-cyan-400">12ms</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Throughput</p>
                <p className="text-xl font-mono text-cyan-400">2.4 Gbps</p>
              </div>
            </div>
          </div>
        </Card>

        {/* Stats Row - Smaller Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total CVEs" value={stats.totalCVEs} hint="8 critical" trend="up" />
          <StatCard label="High-Risk Nodes" value={stats.highRiskNodes} hint="3 new today" trend="down" />
          <StatCard label="Active Threats" value={stats.activeThreats} hint="1 high severity" trend="neutral" />
          <StatCard label="Mitigated" value={stats.mitigated} hint="This month" trend="up" />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-0">
          {/* Active Threats - Medium Card */}
          <div className="lg:col-span-2">
            <Card size="medium" className="h-full flex flex-col">
              <CardHeader
                title="Active Threats"
                icon={<Shield className="text-purple-400" size={20} />}
              />
              <div className="flex-1 overflow-y-auto space-y-3">
                {activeThreats.map((threat) => (
                  <Card
                    key={threat.id}
                    size="small"
                    pulse={threat.severity === 'high'}
                    className="border-purple-500/30 bg-purple-500/10"
                  >
                    <div className="flex items-center justify-between">
                      <span
                        className={`text-sm font-mono ${threat.severity === 'high' ? 'glitch-text' : ''}`}
                        data-text={threat.name}
                      >
                        {threat.name}
                      </span>
                      <span
                        className={`text-xs px-2 py-1 rounded ${
                          threat.severity === 'high'
                            ? 'bg-red-500/20 text-red-300'
                            : threat.severity === 'medium'
                              ? 'bg-yellow-500/20 text-yellow-300'
                              : 'bg-green-500/20 text-green-300'
                        }`}
                      >
                        {threat.severity}
                      </span>
                    </div>
                    <div className="mt-2 text-xs text-gray-400 uppercase tracking-wider">
                      Status: {threat.status}
                    </div>
                  </Card>
                ))}
              </div>
            </Card>
          </div>

          {/* Right Column */}
          <div className="flex flex-col gap-6">
            {/* Risk Heatmap Preview - Medium Card */}
            <Card size="medium" className="flex-1 flex flex-col">
              <CardHeader
                title="Risk Heatmap"
                icon={<TrendingUp className="text-pink-400" size={20} />}
              />
              <div className="flex-1 grid grid-cols-4 gap-2">
                {Array.from({ length: 16 }).map((_, i) => (
                  <div
                    key={i}
                    className="aspect-square rounded border"
                    style={{
                      backgroundColor: `rgba(${255 - i * 10}, ${100 + i * 5}, ${200 - i * 8}, 0.3)`,
                      borderColor: `rgba(${255 - i * 10}, ${100 + i * 5}, ${200 - i * 8}, 0.6)`,
                    }}
                  />
                ))}
              </div>
            </Card>

            {/* Recent Alerts Timeline - Medium Card */}
            <Card size="medium" className="flex-1 flex flex-col">
              <CardHeader
                title="Recent Alerts"
                icon={<Clock className="text-cyan-400" size={20} />}
              />
              <div className="flex-1 overflow-y-auto space-y-3">
                {recentAlerts.map((alert) => (
                  <div key={alert.id} className="flex items-start gap-3">
                    <div
                      className={`h-2 w-2 rounded-full mt-1.5 ${
                        alert.severity === 'high'
                          ? 'bg-red-500'
                          : alert.severity === 'medium'
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                      }`}
                      style={{
                        boxShadow:
                          alert.severity === 'high'
                            ? '0 0 6px rgba(239, 68, 68, 0.8)'
                            : alert.severity === 'medium'
                              ? '0 0 6px rgba(234, 179, 8, 0.8)'
                              : '0 0 6px rgba(34, 197, 94, 0.8)',
                      }}
                    />
                    <div className="flex-1">
                      <div className="text-sm text-gray-200">{alert.type}</div>
                      <div className="text-xs text-gray-500 mt-1">{alert.time}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      </div>
    </TelemetryLayout>
  );
}
