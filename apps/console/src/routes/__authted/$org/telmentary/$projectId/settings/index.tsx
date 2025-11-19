import { createFileRoute, Navigate } from '@tanstack/react-router';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/settings/')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();

  return <Navigate to="/__authted/$org/telmentary/$projectId/settings/general" params={{ org, projectId }} />;
}
