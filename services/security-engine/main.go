// CodeTwin's offline review planner uses a bounded Flow -> Task -> Specialist model.
// PentAGI-inspired architecture; no PentAGI packages, proprietary APIs or tools are embedded.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const protocolVersion = 1

type request struct {
	ProtocolVersion int          `json:"protocol_version"`
	Objective       string       `json:"objective"`
	History         []memoryHint `json:"history,omitempty"`
}
type memoryHint struct {
	Role   string `json:"role"`
	Status string `json:"status"`
}
type task struct {
	Role      string   `json:"role"`
	Objective string   `json:"objective"`
	DependsOn []string `json:"depends_on"`
}
type proposal struct {
	Tasks     []task `json:"tasks"`
	Rationale string `json:"rationale"`
}

var specialists = []struct {
	role      string
	objective string
	keywords  []string
}{
	{"secrets", "Inspect indexed source for credential and secret exposure evidence", []string{"secret", "credential", "token", "password", "key exposure"}},
	{"qa", "Discover existing test evidence and coverage gaps without running code", []string{"qa", "test", "coverage", "reliability", "quality"}},
	{"database", "Review SQL and database schema artifacts without live connections", []string{"database", "sql", "schema", "query", "migration"}},
	{"runtime", "Inspect runtime and deployment configuration artifacts", []string{"runtime", "docker", "container", "deploy", "configuration", "config"}},
}

// plan is intentionally read-only. A proposed task is not permission to run it.
func plan(r request) (proposal, error) {
	objective := strings.TrimSpace(r.Objective)
	if r.ProtocolVersion != protocolVersion || len(objective) == 0 || len(objective) > 2000 {
		return proposal{}, errors.New("invalid protocol version or review objective")
	}
	if len(r.History) > 12 {
		return proposal{}, errors.New("memory summary must contain at most 12 entries")
	}
	for _, hint := range r.History {
		allowed := hint.Role == "scout" || hint.Role == "source"
		for _, specialist := range specialists {
			allowed = allowed || hint.Role == specialist.role
		}
		if !allowed || (hint.Status != "completed" && hint.Status != "failed") {
			return proposal{}, errors.New("invalid memory role/status summary")
		}
	}
	tasks := []task{
		{Role: "scout", Objective: "Inventory the approved indexed project", DependsOn: []string{}},
		{Role: "source", Objective: "Review indexed source and verified hashes", DependsOn: []string{"scout"}},
	}
	lower := strings.ToLower(objective)
	matches := make([]bool, len(specialists))
	found := false
	for i, specialist := range specialists {
		for _, keyword := range specialist.keywords {
			if strings.Contains(lower, keyword) {
				matches[i] = true
				found = true
				break
			}
		}
	}
	// Historical failures must never narrow a broad review objective.
	explicitMatch := found
	// Historical failures can suggest a targeted follow-up, but cannot authorize it.
	memorySuggested := false
	for i, specialist := range specialists {
		for _, hint := range r.History {
			if hint.Role == specialist.role && hint.Status == "failed" && !matches[i] {
				matches[i] = true
				found = true
				memorySuggested = true
			}
		}
	}
	// Broad objectives receive the audited full passive review, never active probes.
	for i, specialist := range specialists {
		if matches[i] || !explicitMatch {
			tasks = append(tasks, task{
				Role: specialist.role, Objective: specialist.objective, DependsOn: []string{"source"},
			})
		}
	}
	rationale := "Offline Go specialist planning; Rust must validate and approve this passive review before execution."
	if memorySuggested {
		rationale += " Includes prior failed passive specialist roles from project-scoped SQLite memory."
	}
	return proposal{Tasks: tasks, Rationale: rationale}, nil
}

func run(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 4097))
	decoder.DisallowUnknownFields()
	var r request
	if err := decoder.Decode(&r); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request must contain exactly one JSON object")
	}
	p, err := plan(r)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(p)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--health" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"engine": "codetwin-security", "protocol_version": protocolVersion,
			"storage": "rust-sqlite", "functions": []string{"plan", "dispatch", "refine", "followup"},
		})
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--dispatch" {
		if err := runDispatch(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "security engine rejected dispatch:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--followup" {
		if err := runFollowup(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "security engine rejected follow-up:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--refine" {
		if err := runRefine(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "security engine rejected refinement:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "unsupported Go security engine argument")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "security engine rejected request:", err)
		os.Exit(1)
	}
}
