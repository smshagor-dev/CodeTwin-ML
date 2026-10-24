package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

)

type refineRequest struct {
	ProtocolVersion int        `json:"protocol_version"`
	Current         proposal   `json:"current"`
	Operations      []refineOp `json:"operations"`
}
type refineOp struct {
	Op        string `json:"op"`
	Role      string `json:"role"`
	Objective string `json:"objective,omitempty"`
	AfterRole string `json:"after_role,omitempty"`
}

var auditedRoles = []string{"scout", "source", "secrets", "qa", "database", "runtime"}

func roleID(role string) int64 {
	for i, expected := range auditedRoles {
		if role == expected {
			return int64(i + 1)
		}
	}
	return 0
}
func validTaskProposal(p proposal) error {
	if len(p.Tasks) < 2 || len(p.Tasks) > 6 || len(p.Rationale) > 1200 ||
		strings.TrimSpace(p.Rationale) == "" {
		return errors.New("invalid current task proposal")
	}
	positions := make(map[string]int, len(p.Tasks))
	for i, task := range p.Tasks {
		if roleID(task.Role) == 0 || len(task.Objective) > 300 ||
			strings.TrimSpace(task.Objective) == "" || len(task.DependsOn) > 4 {
			return errors.New("invalid task or objective")
		}
		if i > 0 && roleID(task.Role) <= roleID(p.Tasks[i-1].Role) {
			return errors.New("task roles must follow audited order")
		}
		positions[task.Role] = i
	}
	if p.Tasks[0].Role != "scout" || p.Tasks[1].Role != "source" {
		return errors.New("mandatory first tasks missing")
	}
	for i, task := range p.Tasks {
		seen := map[string]bool{}
		for _, dep := range task.DependsOn {
			pos, ok := positions[dep]
			if !ok || pos >= i || seen[dep] {
				return errors.New("invalid task dependencies")
			}
			seen[dep] = true
		}
		if (i == 0 && len(task.DependsOn) != 0) ||
			(i == 1 && (len(task.DependsOn) != 1 || task.DependsOn[0] != "scout")) ||
			(i > 1 && !seen["source"]) {
			return errors.New("mandatory dependency missing")
		}
	}
	return nil
}

// refinePlan computes an independent candidate from the immutable approved-role
// vocabulary. Nothing is written to the caller's plan. The complete result
// must pass the same dependency checks as a newly proposed passive review.
// This implementation is specific to CodeTwin's six registered specialists.
func refinePlan(req refineRequest) (proposal, error) {
	if req.ProtocolVersion != protocolVersion || len(req.Operations) < 1 || len(req.Operations) > 8 {
		return proposal{}, errors.New("unsupported refinement protocol or operation count")
	}
	if err := validTaskProposal(req.Current); err != nil {
		return proposal{}, err
	}

	// Each task is a value, so edits to this candidate cannot mutate the
	// original proposal or its dependency lists.
	selected := make(map[string]task, len(req.Current.Tasks))
	for _, original := range req.Current.Tasks {
		selected[original.Role] = original
	}
	visited := make(map[string]bool, len(req.Operations))
	for _, change := range req.Operations {
		if roleID(change.Role) <= 2 {
			return proposal{}, errors.New("mandatory or unregistered role cannot be patched")
		}
		if visited[change.Role] {
			return proposal{}, errors.New("multiple edits to one specialist are ambiguous")
		}
		visited[change.Role] = true
		current, present := selected[change.Role]
		switch change.Op {
		case "add":
			objective := strings.TrimSpace(change.Objective)
			if present || objective == "" || len(change.Objective) > 300 {
				return proposal{}, errors.New("invalid or duplicate added specialist")
			}
			selected[change.Role] = task{
				Role: change.Role, Objective: objective, DependsOn: []string{"source"},
			}
		case "modify":
			objective := strings.TrimSpace(change.Objective)
			if !present || objective == "" || len(change.Objective) > 300 {
				return proposal{}, errors.New("invalid specialist objective modification")
			}
			current.Objective = objective
			selected[change.Role] = current
		case "remove":
			if !present {
				return proposal{}, errors.New("cannot remove missing specialist")
			}
			delete(selected, change.Role)
		case "reorder":
			return proposal{}, errors.New("audited specialist order cannot be changed")
		default:
			return proposal{}, errors.New("unknown task patch action")
		}
	}

	// The approved role registry, rather than an LLM-controlled index or
	// insertion instruction, defines all ordering. Existing dependencies
	// survive unchanged; final validation rejects dangling references.
	result := proposal{
		Tasks: make([]task, 0, len(selected)),
		Rationale: "Local CodeTwin refinement of an unapproved passive review; Rust approval is still required.",
	}
	for _, role := range auditedRoles {
		if chosen, ok := selected[role]; ok {
			result.Tasks = append(result.Tasks, chosen)
		}
	}
	if err := validTaskProposal(result); err != nil {
		return proposal{}, fmt.Errorf("unsafe refinement rejected: %w", err)
	}
	return result, nil
}

func runRefine(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 8193))
	decoder.DisallowUnknownFields()
	var req refineRequest
	if err := decoder.Decode(&req); err != nil {
		return fmt.Errorf("invalid refine request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("refine request must contain one JSON object")
	}
	result, err := refinePlan(req)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
