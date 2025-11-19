import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ui/theme-toggle';
import { createFileRoute, Link, Outlet, useLocation } from '@tanstack/react-router';
import {
  BadgeCheck,
  BetweenHorizonalStart,
  Clock4,
  Settings2,
  TriangleAlert,
  BarChart3,
  LayoutDashboard,
  Network,
  Shield,
  Workflow,
  AlertCircle,
  BookOpen,
  FileText,
} from 'lucide-react';
import { useMemo } from 'react';

type ProjectSummary = {
  slug: string;
  name: string;
  orgSlug: string;
  orgName: string;
  status: string;
  updatedAt: string;
  metrics: {
    errors: number;
    p99: string;
  };
};

export const Route = createFileRoute('/__authted/$org/telmentary')({
  component: RouteComponent,
});

function RouteComponent() {
  const { pathname } = useLocation();
  const { org } = Route.useParams();

  const activeProject = useMemo(
    (): ProjectSummary => ({
      slug: 'project',
      name: 'Pleroma Project',
      orgSlug: org,
      orgName: 'Pleroma',
      status: 'Active',
      updatedAt: new Date().toISOString(),
      metrics: {
        errors: 124,
        p99: '612ms',
      },
    }),
    [org]
  );

  const links = [
    {
      name: 'Dashboard',
      path: '/$org/telmentary/$projectId/',
      icon: <LayoutDashboard size={16} />,
    },
    {
      name: 'Petri Net Studio',
      path: '/$org/telmentary/$projectId/petri-net',
      icon: <Workflow size={16} />,
    },
    {
      name: 'Threat Intelligence',
      path: '/$org/telmentary/$projectId/threat-detection',
      icon: <Shield size={16} />,
    },
    {
      name: 'Defense Simulator',
      path: '/$org/telmentary/$projectId/defense-simulation',
      icon: <Network size={16} />,
    },
    {
      name: 'CAPEC Library',
      path: '/$org/telmentary/$projectId/capec',
      icon: <BookOpen size={16} />,
    },
    {
      name: 'CVE Vulnerabilities',
      path: '/$org/telmentary/$projectId/cve',
      icon: <AlertCircle size={16} />,
    },
    {
      name: 'System Logs',
      path: '/$org/telmentary/$projectId/logs',
      icon: <BetweenHorizonalStart size={16} />,
    },
    {
      name: 'Settings',
      path: '/$org/telmentary/$projectId/settings',
      icon: <Settings2 size={16} />,
    },
  ];

  const isLinkActive = (linkPath: string) => {
    const resolvedPath = linkPath
      .replace('$org', activeProject.orgSlug)
      .replace('$projectId', activeProject.slug);
    return pathname === resolvedPath;
  };

  return (
    <div className="flex h-full overflow-hidden">
      <aside className="w-80 h-full border border-gray-800 relative flex-shrink-0 bg-black/40">
        <Brackets />

        <div className="border-b border-gray-800 px-4 py-3">
          <div>
            <p className="text-[11px] uppercase tracking-[0.35em] text-gray-500">Project</p>
            <p className="mt-2 text-sm font-medium text-white">{activeProject.name}</p>
            <p className="mt-1 text-[10px] uppercase tracking-[0.35em] text-gray-600">
              {activeProject.orgName}
            </p>
          </div>

          <div className="mt-4 flex items-center text-xs text-gray-400">
            <span className="inline-flex items-center gap-1 text-emerald-300">
              <BadgeCheck size={14} />
              {activeProject.status}
            </span>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px] uppercase tracking-[0.3em] text-gray-500">
            <span className="inline-flex items-center gap-2">
              <Clock4 size={12} /> Updated
            </span>
            <span className="text-gray-400">
              {new Intl.DateTimeFormat('en-GB', {
                day: '2-digit',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false,
              }).format(new Date(activeProject.updatedAt))}
            </span>
          </div>
        </div>

        <div className="px-3 py-4 space-y-6 overflow-y-auto h-[calc(100%-5.5rem)] pb-16">
          <section className="space-y-3">
            <p className="text-[11px] uppercase tracking-[0.35em] text-gray-600">Overview</p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded border border-gray-800 bg-black/30 p-2">
                <p className="text-[10px] uppercase tracking-[0.3em] text-gray-500">Errors</p>
                <p className="mt-1 text-base text-white">{activeProject.metrics.errors}</p>
              </div>
              <div className="rounded border border-gray-800 bg-black/30 p-2">
                <p className="text-[10px] uppercase tracking-[0.3em] text-gray-500">P99 latency</p>
                <p className="mt-1 text-base text-white">{activeProject.metrics.p99}</p>
              </div>
            </div>
          </section>

          <nav className="space-y-3">
            <p className="text-[11px] uppercase tracking-[0.35em] text-gray-600">Navigate</p>
            {links.map((link) => {
              const isActive = isLinkActive(link.path);
              return (
                <Link
                  key={link.name}
                  to={link.path}
                  params={{
                    org: activeProject.orgSlug,
                    projectId: activeProject.slug,
                  }}
                >
                  <div className="relative">
                    <Button
                      icon={
                        <span
                          className={isActive ? 'text-cyan-400' : 'text-gray-400'}
                          style={
                            isActive
                              ? {
                                  filter: 'drop-shadow(0 0 8px rgba(93, 229, 255, 0.8))',
                                  transition: 'all 0.3s ease',
                                }
                              : {}
                          }
                        >
                          {link.icon}
                        </span>
                      }
                      showBrackets={isActive}
                      intent="ghost"
                      size="sm"
                      className={`justify-start gap-3 px-3 transition-all duration-300 ${
                        isActive
                          ? 'bg-white/10 text-white border-gray-700 shadow-[0_0_15px_rgba(93,229,255,0.3)]'
                          : 'text-gray-400 hover:text-cyan-400 hover:bg-white/5'
                      }`}
                    >
                      {link.name}
                    </Button>
                  </div>
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="absolute bottom-0 w-full border-t border-gray-800 px-4 py-3 text-[11px] uppercase tracking-[0.3em] text-gray-600 flex items-center justify-between">
          <span>Pleroma CyberNet</span>
          <ThemeToggle />
        </div>
      </aside>

      <div className="flex-1 min-w-0 min-h-0 flex flex-col overflow-hidden ml-5">
        <Outlet />
      </div>
    </div>
  );
}
