// inspect.go implements the `why inspect` command: static analysis of a
// binary's headers and dependency graph, without running it.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"why/internal/evidence"
	"why/internal/inspect/elf"
	"why/internal/inspect/pe"
)

// inspectPipeline inspects rest[0] statically and prints the result. It
// returns 0 on success, or a why tool failure when the target is missing or
// not a parseable PE/ELF image.
func inspectPipeline(rest []string, jsonOut bool) (int, error) {
	if len(rest) == 0 {
		return 0, &exitError{code: 1, msg: "why: inspect: missing target"}
	}
	target := rest[0]
	if _, err := os.Stat(target); err != nil {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: inspect: target not found: %s", target)}
	}
	kind, recognized := sniffKind(target)
	if !recognized {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: inspect: %s is not a recognized PE or ELF image", target)}
	}

	g := inspectGraph(target, kind)
	if err, isErr := g.(error); isErr {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: inspect: %v", err)}
	}

	if jsonOut {
		return 0, renderInspectJSON(g, kind)
	}
	renderInspectHuman(g, kind, target)
	return 0, nil
}

// inspectJSON is the structured --json output of the inspect command.
type inspectJSON struct {
	Kind    string   `json:"kind"`
	Target  string   `json:"target"`
	Machine string   `json:"machine"`
	Class   string   `json:"class,omitempty"`
	Interp  string   `json:"interp,omitempty"`
	Imports []string `json:"imports,omitempty"`
	Nodes   []struct {
		Module string `json:"module"`
		Status string `json:"status"`
		Source string `json:"source,omitempty"`
	} `json:"nodes"`
}

func renderInspectJSON(g any, kind evidence.Kind) error {
	out := &inspectJSON{Kind: string(kind)}
	switch v := g.(type) {
	case *pe.Graph:
		out.Target = v.Target
		out.Machine = v.Machine
		for _, imp := range v.Imports {
			out.Imports = append(out.Imports, imp.DLL)
		}
		out.Nodes = make([]struct {
			Module string `json:"module"`
			Status string `json:"status"`
			Source string `json:"source,omitempty"`
		}, 0, len(v.Nodes))
		for _, n := range v.Nodes {
			out.Nodes = append(out.Nodes, struct {
				Module string `json:"module"`
				Status string `json:"status"`
				Source string `json:"source,omitempty"`
			}{n.Module, string(n.Status), n.Source})
		}
	case *elf.Graph:
		out.Target = v.Target
		out.Machine = v.TargetArch
		out.Class = v.TargetClass
		out.Interp = v.Interp
		out.Nodes = make([]struct {
			Module string `json:"module"`
			Status string `json:"status"`
			Source string `json:"source,omitempty"`
		}, 0, len(v.Nodes))
		for _, n := range v.Nodes {
			out.Nodes = append(out.Nodes, struct {
				Module string `json:"module"`
				Status string `json:"status"`
				Source string `json:"source,omitempty"`
			}{n.Module, string(n.Status), n.Source})
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")
	return nil
}

func renderInspectHuman(g any, kind evidence.Kind, target string) {
	fmt.Printf("why inspect — %s\n", target)
	switch v := g.(type) {
	case *pe.Graph:
		fmt.Printf("kind: pe   machine: %s   subsystem: %s\n", v.Machine, v.Subsystem)
		fmt.Printf("imports (%d):\n", len(v.Imports))
		for _, imp := range v.Imports {
			fmt.Printf("  - %s\n", imp.DLL)
		}
		fmt.Printf("dependencies (%d):\n", len(v.Nodes)-1)
		for _, n := range v.Nodes[1:] {
			where := ""
			if n.Source != "" {
				where = "  [" + n.Source + "]"
			}
			fmt.Printf("  - %s  %s%s\n", n.Module, n.Status, where)
		}
	case *elf.Graph:
		fmt.Printf("kind: elf   arch: %s   class: %s\n", v.TargetArch, v.TargetClass)
		if v.Interp != "" {
			fmt.Printf("interp: %s\n", v.Interp)
		}
		fmt.Printf("DT_NEEDED (%d):\n", len(v.Needed))
		for _, n := range v.Needed {
			fmt.Printf("  - %s\n", n)
		}
		fmt.Printf("dependencies (%d):\n", len(v.Nodes)-1)
		for _, n := range v.Nodes[1:] {
			where := ""
			if n.Source != "" {
				where = "  [" + n.Source + "]"
			}
			fmt.Printf("  - %s  %s%s\n", n.Module, n.Status, where)
		}
	}
}
