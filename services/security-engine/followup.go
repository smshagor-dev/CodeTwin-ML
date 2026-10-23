package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A follow-up can only narrow an already authorized, terminal review.
// It never approves, retries or executes a task.
type followupRequest struct {
	ProtocolVersion int            `json:"protocol_version"`
	RunStatus       string         `json:"run_status"`
	Tasks           []followupTask `json:"tasks"`
}
type followupTask struct {
	Role   string `json:"role"`
	Status string `json:"status"`
}
type followupAdvice struct {
	Suggested bool      `json:"suggested"`
	Proposal  *proposal `json:"proposal,omitempty"`
	Reason    string    `json:"reason"`
}

func planFollowup(req followupRequest) (followupAdvice, error) {
	var no = followupAdvice{Suggested: false, Reason: "No incomplete authorized roles need a follow-up"}
	if req.ProtocolVersion != protocolVersion || (req.RunStatus != "failed" && req.RunStatus != "interrupted") {
		return no, errors.New("follow-ups require a failed or interrupted authorized review")
	}
	if len(req.Tasks) < 2 || len(req.Tasks) > 6 || req.Tasks[0].Role != "scout" || req.Tasks[1].Role != "source" {
		return no, errors.New("invalid prior specialist selection")
	}
	previous := -1
	for _, task := range req.Tasks {
		position := registeredPosition(task.Role)
		if position <= previous {
			return no, errors.New("unregistered, duplicate or unordered prior role")
		}
		previous = position
		switch task.Status {
		case "completed", "failed", "skipped", "cancelled", "interrupted":
		default:
			return no, errors.New("follow-up requires terminal task states")
		}
	}
	// A failed source gate invalidates every downstream claim. Reassess only
	// source prerequisites before suggesting additional optional analyzers.
	tasks := []task{
		{Role: "scout", Objective: "Recheck the approved indexed project inventory", DependsOn: []string{}},
		{Role: "source", Objective: "Revalidate source evidence and verified hashes", DependsOn: []string{"scout"}},
	}
	if req.Tasks[1].Status == "completed" {
		for _, prior := range req.Tasks[2:] {
			if prior.Status == "completed" {
				continue
			}
			objective := ""
			for _, specialist := range specialists {
				if specialist.role == prior.Role {
					objective = specialist.objective
					break
				}
			}
			if objective == "" {
				return no, errors.New("unrecognized follow-up specialist")
			}
			tasks = append(tasks, task{
				Role: prior.Role, Objective: objective, DependsOn: []string{"source"},
			})
		}
		if len(tasks) == 2 {
			return no, nil
		}
	}
	p := proposal{
		Tasks:     tasks,
		Rationale: "Adaptive follow-up for incomplete previously authorized passive roles; review and new approval required. No new role or target is authorized.",
	}
	if err := validTaskProposal(p); err != nil {
		return no, fmt.Errorf("invalid follow-up task plan: %w", err)
	}
	return followupAdvice{Suggested: true, Proposal: &p, Reason: "Incomplete passive review needs a fresh, scoped approval"}, nil
}

func runFollowup(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 4097))
	decoder.DisallowUnknownFields()
	var req followupRequest
	if err := decoder.Decode(&req); err != nil {
		return fmt.Errorf("invalid follow-up request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("follow-up accepts exactly one JSON object")
	}
	result, err := planFollowup(req)
	if err != nil {
		return err
	}
	if len(result.Reason) > 300 || strings.TrimSpace(result.Reason) == "" {
		return errors.New("invalid follow-up explanation")
	}
	return json.NewEncoder(output).Encode(result)
}
