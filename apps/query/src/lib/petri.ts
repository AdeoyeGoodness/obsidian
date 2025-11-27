import type { Client } from "pg";

export type ProcessTask = {
  id: string;
  name?: string;
  next?: string[];
  kind?: "task" | "gateway";
};

export type ProcessDefinition = {
  tasks?: ProcessTask[];
  metadata?: Record<string, unknown>;
};

export type PetriNode = {
  id: string;
  type: "place" | "transition";
  data: {
    label: string;
    tokens?: number;
  };
  position: {
    x: number;
    y: number;
  };
};

export type PetriEdge = {
  id: string;
  source: string;
  target: string;
};

export type PetriNetStructure = {
  nodes: PetriNode[];
  edges: PetriEdge[];
};

export const buildDefaultStructure = (): PetriNetStructure => ({
  nodes: [],
  edges: [],
});

export const generatePetriNetStructure = (
  definition?: ProcessDefinition,
  activityCounts: Record<string, number> = {}
): PetriNetStructure => {
  const tasks = definition?.tasks ?? [];
  if (!tasks.length) {
    return buildDefaultStructure();
  }

  const nodes: PetriNode[] = [];
  const edges: PetriEdge[] = [];

  tasks.forEach((task, index) => {
    nodes.push({
      id: task.id,
      type: task.kind === "gateway" ? "transition" : "place",
      data: {
        label: task.name ?? task.id,
        tokens: task.kind === "gateway" ? 0 : activityCounts[task.id] ?? 0,
      },
      position: {
        x: (index % 4) * 220,
        y: Math.floor(index / 4) * 180,
      },
    });

    task.next?.forEach((nextId, nextIndex) => {
      edges.push({
        id: `${task.id}-${nextId}-${nextIndex}`,
        source: task.id,
        target: nextId,
      });
    });
  });

  return { nodes, edges };
};

export async function fetchActivityCounts(
  db: Client,
  processId: string
): Promise<Record<string, number>> {
  const result = await db.query(
    `
    SELECT payload->>'taskId' AS task_id, COUNT(*)::int AS count
    FROM process_events
    WHERE process_id = $1
      AND payload ? 'taskId'
    GROUP BY payload->>'taskId'
    `,
    [processId]
  );

  return result.rows.reduce<Record<string, number>>((acc, row) => {
    if (row.task_id) {
      acc[row.task_id] = Number(row.count);
    }
    return acc;
  }, {});
}

