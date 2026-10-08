// The v1 graph routes accept up to 1000 rows per page (api_v1.paginate_collection)
// and serve only their first page of 100 when called without paging params.
export const GRAPH_PAGE_LIMIT = 1000;

type GraphLike = { nodes: unknown[]; edges: unknown[] };

export type GraphPage<T> = {
  data: T;
  meta?: { next_cursor?: string | null };
};

/**
 * Read every page of a `/v1/graph`-style object payload.
 *
 * Nodes and edges are paged together under one cursor; every other member
 * (counts, summaries) repeats on each page, so the first page's copy is kept.
 */
export async function readAllGraphPages<T extends GraphLike>(
  fetchPage: (query: string) => Promise<GraphPage<T>>,
): Promise<T> {
  const first = await fetchPage(`?limit=${GRAPH_PAGE_LIMIT}`);
  const nodes = [...first.data.nodes];
  const edges = [...first.data.edges];
  const seen = new Set<string>();
  let cursor = first.meta?.next_cursor ?? null;
  while (cursor) {
    if (seen.has(cursor)) {
      throw new Error(`graph paging repeated cursor ${cursor}`);
    }
    seen.add(cursor);
    const page = await fetchPage(
      `?limit=${GRAPH_PAGE_LIMIT}&cursor=${encodeURIComponent(cursor)}`,
    );
    nodes.push(...page.data.nodes);
    edges.push(...page.data.edges);
    cursor = page.meta?.next_cursor ?? null;
  }
  return { ...first.data, nodes, edges };
}
