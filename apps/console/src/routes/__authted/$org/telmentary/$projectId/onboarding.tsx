import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { Upload, Map, Settings, Sparkles, ChevronRight, FileText } from 'lucide-react';
import { useState } from 'react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/onboarding')({
  component: RouteComponent,
});

const steps = [
  { id: 1, name: 'Upload Data', icon: Upload },
  { id: 2, name: 'Map Entities', icon: Map },
  { id: 3, name: 'Define Constraints', icon: Settings },
  { id: 4, name: 'Generate Petri Net', icon: Sparkles },
];

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const [currentStep, setCurrentStep] = useState(1);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setUploadedFile(file);
    }
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="space-y-6">
            <div className="border-2 border-dashed border-cyan-500/30 bg-cyan-500/5 p-12 rounded-lg text-center">
              <Upload className="mx-auto mb-4 text-cyan-400" size={48} />
              <label className="cursor-pointer">
                <input
                  type="file"
                  className="hidden"
                  onChange={handleFileUpload}
                  accept=".json,.csv,.xml"
                />
                <div className="text-sm text-gray-300 mb-2">
                  {uploadedFile ? uploadedFile.name : 'Click to upload or drag and drop'}
                </div>
                <div className="text-xs text-gray-500 uppercase tracking-wider">
                  JSON, CSV, or XML files
                </div>
              </label>
            </div>
            {uploadedFile && (
              <div className="border border-green-500/30 bg-green-500/10 p-4 rounded">
                <div className="text-sm text-green-300">✓ File uploaded successfully</div>
                <div className="text-xs text-gray-400 mt-1">{uploadedFile.name}</div>
              </div>
            )}
          </div>
        );
      case 2:
        return (
          <div className="space-y-4">
            <div className="text-sm text-gray-400 mb-4">Map your business process entities:</div>
            <div className="space-y-3">
              {['Process', 'Resource', 'Event', 'Gateway'].map((entity) => (
                <div key={entity} className="border border-gray-700 bg-black/40 p-4 rounded">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-200 font-mono">{entity}</span>
                    <select className="bg-black/60 border border-gray-700 text-xs text-gray-300 px-3 py-1 rounded">
                      <option>Select mapping...</option>
                      <option>Column A</option>
                      <option>Column B</option>
                      <option>Column C</option>
                    </select>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      case 3:
        return (
          <div className="space-y-4">
            <div className="text-sm text-gray-400 mb-4">Define process constraints:</div>
            <div className="space-y-3">
              <div className="border border-gray-700 bg-black/40 p-4 rounded">
                <label className="text-xs text-gray-500 uppercase tracking-wider mb-2 block">
                  Max Concurrent Processes
                </label>
                <input
                  type="number"
                  className="w-full bg-black/60 border border-gray-700 text-sm text-gray-300 px-3 py-2 rounded font-mono"
                  defaultValue="10"
                />
              </div>
              <div className="border border-gray-700 bg-black/40 p-4 rounded">
                <label className="text-xs text-gray-500 uppercase tracking-wider mb-2 block">
                  Timeout (seconds)
                </label>
                <input
                  type="number"
                  className="w-full bg-black/60 border border-gray-700 text-sm text-gray-300 px-3 py-2 rounded font-mono"
                  defaultValue="300"
                />
              </div>
              <div className="border border-gray-700 bg-black/40 p-4 rounded">
                <label className="text-xs text-gray-500 uppercase tracking-wider mb-2 block">
                  Retry Attempts
                </label>
                <input
                  type="number"
                  className="w-full bg-black/60 border border-gray-700 text-sm text-gray-300 px-3 py-2 rounded font-mono"
                  defaultValue="3"
                />
              </div>
            </div>
          </div>
        );
      case 4:
        return (
          <div className="space-y-6 text-center">
            <Sparkles className="mx-auto text-cyan-400" size={64} />
            <div className="text-lg text-gray-200">Ready to generate Petri Net</div>
            <div className="text-sm text-gray-400">
              Click the button below to generate your Petri Net model from the configured data.
            </div>
            <Button
              onClick={() => alert('Petri Net generation would start here')}
              icon={<Sparkles size={16} />}
              className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10 mx-auto"
            >
              Generate Petri Net
            </Button>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Business Process Onboarding">
      <div className="px-6 py-5 flex-1 min-h-0 flex flex-col gap-5 overflow-hidden">
        {/* Progress Steps */}
        <div className="flex items-center justify-between flex-shrink-0">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            const isActive = currentStep === step.id;
            const isCompleted = currentStep > step.id;
            return (
              <div key={step.id} className="flex items-center flex-1">
                <div className="flex items-center gap-3 flex-1">
                  <div
                    className={`w-10 h-10 rounded-full border-2 flex items-center justify-center ${
                      isActive
                        ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400'
                        : isCompleted
                          ? 'border-green-500 bg-green-500/20 text-green-400'
                          : 'border-gray-700 bg-black/40 text-gray-500'
                    }`}
                  >
                    <Icon size={20} />
                  </div>
                  <div className="flex-1">
                    <div
                      className={`text-xs uppercase tracking-wider ${
                        isActive ? 'text-cyan-400' : isCompleted ? 'text-green-400' : 'text-gray-500'
                      }`}
                    >
                      {step.name}
                    </div>
                  </div>
                </div>
                {idx < steps.length - 1 && (
                  <ChevronRight
                    className={`mx-2 ${isCompleted ? `text-green-400` : `text-gray-700`}`}
                    size={20}
                  />
                )}
              </div>
            );
          })}
        </div>

        {/* Terminal-style Form */}
        <div className="relative border border-gray-800 bg-black/40 p-6 flex-1 min-h-0 flex flex-col overflow-hidden">
          <Brackets />
          <div className="mb-4 flex-shrink-0">
            <div className="text-xs text-green-400 font-mono mb-1">$ pleroma-onboard --step {currentStep}</div>
            <div className="text-xs text-gray-500 font-mono">Initializing business process data input...</div>
          </div>
          <div className="flex-1 overflow-y-auto">{renderStepContent()}</div>
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between flex-shrink-0">
          <Button
            onClick={() => setCurrentStep(Math.max(1, currentStep - 1))}
            disabled={currentStep === 1}
            className="border-gray-700 text-gray-400"
          >
            Previous
          </Button>
          <Button
            onClick={() => setCurrentStep(Math.min(steps.length, currentStep + 1))}
            disabled={currentStep === steps.length}
            icon={<ChevronRight size={16} />}
            className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10"
          >
            Next
          </Button>
        </div>
      </div>
    </TelemetryLayout>
  );
}
