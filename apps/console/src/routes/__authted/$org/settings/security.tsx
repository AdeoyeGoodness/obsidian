import { createFileRoute } from '@tanstack/react-router';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { ShieldCheck, Key, Lock } from 'lucide-react';

export const Route = createFileRoute('/__authted/$org/settings/security')({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div className="space-y-7 p-6">
      <div>
        <h2 className="text-sm font-semibold text-white uppercase tracking-[0.2em]">Security</h2>
        <p className="mt-2 text-xs text-gray-400">
          Configure security settings and authentication preferences.
        </p>
      </div>

      <div className="grid gap-4">
        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <ShieldCheck className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Two-Factor Authentication</p>
          </div>
          <div className="space-y-3">
            <p className="text-xs text-gray-400">2FA is currently disabled</p>
            <div className="flex justify-end">
              <Button className="w-auto px-4">Enable 2FA</Button>
            </div>
          </div>
        </div>

        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <Key className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">API Keys</p>
          </div>
          <div className="space-y-3">
            <p className="text-xs text-gray-400">Manage API keys for programmatic access</p>
            <div className="flex justify-end">
              <Button intent="ghost" className="w-auto px-4">
                Manage API Keys
              </Button>
            </div>
          </div>
        </div>

        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <Lock className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Session Management</p>
          </div>
          <div className="space-y-3">
            <p className="text-xs text-gray-400">View and manage active sessions</p>
            <div className="flex justify-end">
              <Button intent="ghost" className="w-auto px-4">
                View Sessions
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
