package elf

import (
	"path/filepath"
	"testing"
)

// abs returns the absolute form of path (helper for test assertions).
func abs(t *testing.T, path string) string {
	t.Helper()
	a, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("Abs(%q): %v", path, err)
	}
	return a
}

// nodeByModule returns the node with the given module, failing the test.
func nodeByModule(t *testing.T, g *Graph, module string) Node {
	t.Helper()
	for _, n := range g.Nodes {
		if n.Module == module {
			return n
		}
	}
	t.Fatalf("graph has no node with module %q; nodes: %v", module, modules(g))
	return Node{}
}

// modules returns the Module of every node in order.
func modules(g *Graph) []string {
	var out []string
	for _, n := range g.Nodes {
		out = append(out, n.Module)
	}
	return out
}

// edgeSet returns the edge set of g as a map.
func edgeSet(g *Graph) map[Edge]bool {
	m := make(map[Edge]bool, len(g.Edges))
	for _, e := range g.Edges {
		m[e] = true
	}
	return m
}

// hasEdge reports whether g contains the edge from->to.
func hasEdge(g *Graph, from, to string) bool { return edgeSet(g)[Edge{from, to}] }

// errorsAs asserts err is an *Error and stores it in target.
func errorsAs(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}
