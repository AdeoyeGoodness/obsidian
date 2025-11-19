import { createFileRoute, Navigate } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  component: App,
});

function App() {
  // Auto-redirect to dashboard
  return <Navigate to="/__authted/logbase/telmentary/project/" />;
}
