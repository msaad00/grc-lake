import { expect, test } from "@playwright/test";
import {
  GRAPH_PAGE_LIMIT,
  readAllGraphPages,
} from "../src/lib/api/graph-pages";

// Pure-function checks for the graph cursor walk; no browser page needed.

type Node = { id: string };
type Edge = { id: string };
type Graph = { nodes: Node[]; edges: Edge[]; counts: { total: number } };

function pagedServer(nodes: number, edges: number, pageSize: number) {
  const all = {
    nodes: Array.from({ length: nodes }, (_, i) => ({ id: `n${i}` })),
    edges: Array.from({ length: edges }, (_, i) => ({ id: `e${i}` })),
  };
  const queries: string[] = [];
  const fetchPage = async (query: string) => {
    queries.push(query);
    const params = new URLSearchParams(query.replace(/^\?/, ""));
    const offset = Number(params.get("cursor") ?? "0");
    const end = offset + pageSize;
    const longest = Math.max(nodes, edges);
    return {
      data: {
        nodes: all.nodes.slice(offset, end),
        edges: all.edges.slice(offset, end),
        counts: { total: nodes },
      } as Graph,
      meta: { next_cursor: end < longest ? String(end) : null },
    };
  };
  return { all, queries, fetchPage };
}

test("asks for the largest page and stops after one when nothing remains", async () => {
  const server = pagedServer(3, 2, GRAPH_PAGE_LIMIT);
  const graph = await readAllGraphPages(server.fetchPage);
  expect(server.queries).toEqual([`?limit=${GRAPH_PAGE_LIMIT}`]);
  expect(graph.nodes).toEqual(server.all.nodes);
  expect(graph.edges).toEqual(server.all.edges);
  expect(graph.counts).toEqual({ total: 3 });
});

test("follows next_cursor and concatenates nodes and edges in order", async () => {
  const server = pagedServer(7, 4, 3);
  const graph = await readAllGraphPages(server.fetchPage);
  expect(server.queries).toEqual([
    `?limit=${GRAPH_PAGE_LIMIT}`,
    `?limit=${GRAPH_PAGE_LIMIT}&cursor=3`,
    `?limit=${GRAPH_PAGE_LIMIT}&cursor=6`,
  ]);
  expect(graph.nodes).toEqual(server.all.nodes);
  expect(graph.edges).toEqual(server.all.edges);
});

test("an empty graph is one request", async () => {
  const server = pagedServer(0, 0, 3);
  const graph = await readAllGraphPages(server.fetchPage);
  expect(server.queries).toHaveLength(1);
  expect(graph.nodes).toEqual([]);
  expect(graph.edges).toEqual([]);
});

test("a cursor that repeats fails instead of looping forever", async () => {
  const fetchPage = async () => ({
    data: { nodes: [{ id: "n" }], edges: [], counts: { total: 1 } } as Graph,
    meta: { next_cursor: "same" },
  });
  await expect(readAllGraphPages(fetchPage)).rejects.toThrow(/cursor/);
});

test("a response without a cursor is read as one page", async () => {
  const fetchPage = async () => ({
    data: { nodes: [{ id: "n" }], edges: [{ id: "e" }], counts: { total: 1 } },
    meta: {},
  });
  const graph = await readAllGraphPages<Graph>(fetchPage);
  expect(graph.nodes).toEqual([{ id: "n" }]);
  expect(graph.edges).toEqual([{ id: "e" }]);
});
