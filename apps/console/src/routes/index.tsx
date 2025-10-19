import { createFileRoute, Navigate } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  component: App,
});

function App() {
  // Auto-redirect to dashboard in dev mode
  return <Navigate to="/__authted/sentinel-org/telmentary" />;
}
