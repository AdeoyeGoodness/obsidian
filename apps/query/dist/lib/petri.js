export const buildDefaultStructure = () => ({
    nodes: [],
    edges: [],
});
export const generatePetriNetStructure = (definition, activityCounts = {}) => {
    const tasks = definition?.tasks ?? [];
    if (!tasks.length) {
        return buildDefaultStructure();
    }
    const nodes = [];
    const edges = [];
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
export async function fetchActivityCounts(db, processId) {
    const result = await db.query(`
    SELECT payload->>'taskId' AS task_id, COUNT(*)::int AS count
    FROM process_events
    WHERE process_id = $1
      AND payload ? 'taskId'
    GROUP BY payload->>'taskId'
    `, [processId]);
    return result.rows.reduce((acc, row) => {
        if (row.task_id) {
            acc[row.task_id] = Number(row.count);
        }
        return acc;
    }, {});
}
