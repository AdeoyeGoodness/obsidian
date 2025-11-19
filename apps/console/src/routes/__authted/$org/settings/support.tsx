import { createFileRoute } from '@tanstack/react-router';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { LifeBuoy, MessageSquare, Book, Mail } from 'lucide-react';

export const Route = createFileRoute('/__authted/$org/settings/support')({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div className="space-y-7 p-6">
      <div>
        <h2 className="text-sm font-semibold text-white uppercase tracking-[0.2em]">Support</h2>
        <p className="mt-2 text-xs text-gray-400">
          Get help, contact support, and access documentation.
        </p>
      </div>

      <div className="grid gap-4">
        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <LifeBuoy className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Help & Resources</p>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between border border-gray-800 bg-black/40 p-3 rounded">
              <div className="flex items-center gap-3">
                <Book className="text-gray-400" size={16} />
                <span className="text-sm text-gray-200">Documentation</span>
              </div>
              <Button intent="ghost" size="sm" className="w-auto">
                View Docs
              </Button>
            </div>
            <div className="flex items-center justify-between border border-gray-800 bg-black/40 p-3 rounded">
              <div className="flex items-center gap-3">
                <MessageSquare className="text-gray-400" size={16} />
                <span className="text-sm text-gray-200">Community Forum</span>
              </div>
              <Button intent="ghost" size="sm" className="w-auto">
                Visit Forum
              </Button>
            </div>
          </div>
        </div>

        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <Mail className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Contact Support</p>
          </div>
          <div className="space-y-3">
            <p className="text-xs text-gray-400">
              Need help? Reach out to our support team for assistance.
            </p>
            <div className="flex justify-end">
              <Button className="w-auto px-4">Contact Support</Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
