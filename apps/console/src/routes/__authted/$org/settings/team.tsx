import { createFileRoute } from '@tanstack/react-router';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { Users, UserPlus } from 'lucide-react';

export const Route = createFileRoute('/__authted/$org/settings/team')({
  component: RouteComponent,
});

function RouteComponent() {
  const teamMembers = [
    { id: '1', name: 'Admin User', email: 'admin@pleroma.com', role: 'Owner', status: 'Active' },
    { id: '2', name: 'Developer', email: 'dev@pleroma.com', role: 'Member', status: 'Active' },
  ];

  return (
    <div className="space-y-7 p-6">
      <div>
        <h2 className="text-sm font-semibold text-white uppercase tracking-[0.2em]">Team</h2>
        <p className="mt-2 text-xs text-gray-400">
          Manage team members and their access permissions.
        </p>
      </div>

      <div className="grid gap-4">
        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Users className="text-cyan-400" size={20} />
              <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Team Members</p>
            </div>
            <Button icon={<UserPlus size={16} />} className="w-auto px-4">
              Invite Member
            </Button>
          </div>
          <div className="space-y-3">
            {teamMembers.map((member) => (
              <div
                key={member.id}
                className="flex items-center justify-between border border-gray-800 bg-black/40 p-3 rounded"
              >
                <div>
                  <p className="text-sm text-white">{member.name}</p>
                  <p className="text-xs text-gray-400 mt-1">{member.email}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 uppercase tracking-wider">{member.role}</span>
                  <span className="text-xs text-emerald-300 uppercase tracking-wider">{member.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
