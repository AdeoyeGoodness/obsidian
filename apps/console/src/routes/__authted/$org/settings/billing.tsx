import { createFileRoute } from '@tanstack/react-router';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { CreditCard } from 'lucide-react';

export const Route = createFileRoute('/__authted/$org/settings/billing')({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div className="space-y-7 p-6">
      <div>
        <h2 className="text-sm font-semibold text-white uppercase tracking-[0.2em]">Billing</h2>
        <p className="mt-2 text-xs text-gray-400">
          Manage your subscription, payment methods, and billing history.
        </p>
      </div>

      <div className="grid gap-4">
        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <div className="flex items-center gap-3 mb-4">
            <CreditCard className="text-cyan-400" size={20} />
            <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">Current Plan</p>
          </div>
          <div className="space-y-3">
            <div>
              <p className="text-lg font-semibold text-white">Free Tier</p>
              <p className="text-xs text-gray-400 mt-1">Basic monitoring and analytics</p>
            </div>
            <div className="flex justify-end">
              <Button className="w-auto px-4">Upgrade Plan</Button>
            </div>
          </div>
        </div>

        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500 mb-4">Payment Method</p>
          <div className="space-y-3">
            <p className="text-xs text-gray-400">No payment method on file</p>
            <div className="flex justify-end">
              <Button intent="ghost" className="w-auto px-4">
                Add Payment Method
              </Button>
            </div>
          </div>
        </div>

        <div className="relative border border-gray-800 bg-black/30 p-5">
          <Brackets />
          <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500 mb-4">Billing History</p>
          <div className="space-y-2">
            <p className="text-xs text-gray-400">No billing history available</p>
          </div>
        </div>
      </div>
    </div>
  );
}
