package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"codetwin/security-engine/refinement"
)

type refineRequest struct {
	ProtocolVersion int         `json:"protocol_version"`
	Current         proposal    `json:"current"`
	Operations      []refineOp  `json:"operations"`
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

func refinePlan(req refineRequest) (proposal, error) {
	if req.ProtocolVersion != protocolVersion || len(req.Operations) < 1 || len(req.Operations) > 8 {
		return proposal{}, errors.New("unsupported refinement protocol or operation count")
	}
	if err := validTaskProposal(req.Current); err != nil {
		return proposal{}, err
	}
	planned := make([]refinement.Subtask, 0, len(req.Current.Tasks))
	existing := make(map[string]task, len(req.Current.Tasks))
	for _, current := range req.Current.Tasks {
		planned = append(planned, refinement.Subtask{
			ID: roleID(current.Role), Title: current.Role, Description: current.Objective,
		})
		existing[current.Role] = current
	}
	converted := make([]refinement.Operation, 0, len(req.Operations))
	for _, op := range req.Operations {
		id := roleID(op.Role)
		if id == 0 || op.Role == "scout" || op.Role == "source" {
			return proposal{}, errors.New("mandatory or unregistered role cannot be patched")
		}
		patch := refinement.Operation{Op: op.Op, ID: &id}
		switch op.Op {
		case "add":
			if _, has := existing[op.Role]; has || len(op.Objective) > 300 ||
				strings.TrimSpace(op.Objective) == "" {
				return proposal{}, errors.New("invalid or duplicate added specialist")
			}
			patch.Title, patch.Description = op.Role, strings.TrimSpace(op.Objective)
			// Insert after the last canonical predecessor already selected.
			var after int64
			for _, item := range planned {
				if item.ID < id && item.ID > after {
					after = item.ID
				}
			}
			patch.AfterID = &after
		case "remove":
			if _, has := existing[op.Role]; !has {
				return proposal{}, errors.New("cannot remove missing specialist")
			}
		case "modify":
			if _, has := existing[op.Role]; !has || len(op.Objective) > 300 ||
				strings.TrimSpace(op.Objective) == "" {
				return proposal{}, errors.New("invalid specialist objective modification")
			}
			patch.Description = strings.TrimSpace(op.Objective)
		case "reorder":
			return proposal{}, errors.New("audited specialist order cannot be changed")
		default:
			return proposal{}, errors.New("unknown task patch action")
		}
		converted = append(converted, patch)
	}
	updated, err := refinement.Apply(planned, converted)
	if err != nil {
		return proposal{}, err
	}
	output := proposal{
		Tasks: make([]task, 0, len(updated)),
		Rationale: "Local Go refinement of an unapproved passive review; Rust approval is still required.",
	}
	for _, item := range updated {
		if item.Title == "scout" || item.Title == "source" {
			// Mandatory task titles are immutable; objectives are unchanged.
			output.Tasks = append(output.Tasks, existing[item.Title])
			continue
		}
		if initial, ok := existing[item.Title]; ok {
			initial.Objective = item.Description
			output.Tasks = append(output.Tasks, initial)
		} else {
			output.Tasks = append(output.Tasks, task{
				Role: item.Title, Objective: item.Description, DependsOn: []string{"source"},
			})
		}
	}
	if err := validTaskProposal(output); err != nil {
		return proposal{}, fmt.Errorf("unsafe refinement rejected: %w", err)
	}
	return output, nil
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
