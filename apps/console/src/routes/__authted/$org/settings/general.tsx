import { createFileRoute } from '@tanstack/react-router';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { Settings2 } from 'lucide-react';
import { useState } from 'react';

export const Route = createFileRoute('/__authted/$org/settings/general')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org } = Route.useParams();
  const [orgName, setOrgName] = useState('Pleroma');
  const [orgSlug, setOrgSlug] = useState(org ?? '');

  return (
    <div className="space-y-7 p-6">
      <div>
        <h2 className="text-sm font-semibold text-white uppercase tracking-[0.2em]">General Settings</h2>
        <p className="mt-2 text-xs text-gray-400">
          Configure your organization's basic information and preferences.
        </p>
      </div>

      <div className="grid gap-4">
        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <Settings2 className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Organization Identity</p>
          </div>
          <form className="space-y-4">
            <label className="block space-y-2">
              <p className="text-[11px] uppercase tracking-[0.3em] text-gray-500">Organization Name</p>
              <input
                value={orgName}
                onChange={(event) => setOrgName(event.target.value)}
                className="w-full border border-gray-800 bg-black/40 px-3 py-2 text-sm text-white outline-none focus:border-cyan-500"
                placeholder="Enter organization name"
              />
            </label>
            <label className="block space-y-2">
              <p className="text-[11px] uppercase tracking-[0.3em] text-gray-500">Organization Slug</p>
              <p className="text-[11px] text-gray-500/80">Used in API requests and routing</p>
              <input
                value={orgSlug}
                onChange={(event) => setOrgSlug(event.target.value)}
                className="w-full border border-gray-800 bg-black/40 px-3 py-2 text-sm font-mono text-white outline-none focus:border-cyan-500"
                placeholder="org-slug"
              />
            </label>
            <div className="flex justify-end">
              <Button className="w-auto px-4">Save Changes</Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
