package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// This protocol proposes the next approved, dependency-ready specialist set.
// It never executes tools or mutates persistent state: Rust owns SQLite and approval.
type dispatchRequest struct {
	ProtocolVersion int            `json:"protocol_version"`
	RunStatus       string         `json:"run_status"`
	MaxParallel     int            `json:"max_parallel"`
	Tasks           []dispatchTask `json:"tasks"`
}
type dispatchTask struct {
	Role      string   `json:"role"`
	Status    string   `json:"status"`
	DependsOn []string `json:"depends_on"`
}
type dispatchAdvice struct {
	Ready    []string `json:"ready"`
	Waiting  []string `json:"waiting"`
	Running  []string `json:"running"`
	Terminal bool     `json:"terminal"`
	Reason   string   `json:"reason"`
}

func registeredPosition(role string) int {
	roles := [...]string{"scout", "source", "secrets", "qa", "database", "runtime"}
	for index, candidate := range roles {
		if role == candidate {
			return index
		}
	}
	return -1
}

func decideDispatch(req dispatchRequest) (dispatchAdvice, error) {
	empty := dispatchAdvice{Ready: []string{}, Waiting: []string{}, Running: []string{}}
	if req.ProtocolVersion != protocolVersion || req.MaxParallel < 1 || req.MaxParallel > 2 ||
		len(req.Tasks) < 2 || len(req.Tasks) > 6 {
		return empty, errors.New("invalid dispatch protocol, concurrency limit or specialist count")
	}
	switch req.RunStatus {
	case "planned", "approved", "running", "completed", "failed", "cancelled", "interrupted":
	default:
		return empty, errors.New("unknown review lifecycle status")
	}
	states := map[string]string{}
	positions := map[string]int{}
	previous := -1
	for index, task := range req.Tasks {
		pos := registeredPosition(task.Role)
		if pos <= previous || pos < 0 {
			return empty, errors.New("roles must be unique, registered and ordered")
		}
		previous = pos
		if task.Status != "pending" && task.Status != "running" &&
			task.Status != "completed" && task.Status != "failed" && task.Status != "cancelled" {
			return empty, errors.New("invalid persisted task state")
		}
		if len(task.DependsOn) > 4 {
			return empty, errors.New("too many task dependencies")
		}
		states[task.Role] = task.Status
		positions[task.Role] = index
	}
	if req.Tasks[0].Role != "scout" || req.Tasks[1].Role != "source" {
		return empty, errors.New("source review must follow project reconnaissance")
	}
	for _, task := range req.Tasks {
		seen := map[string]bool{}
		for _, dependency := range task.DependsOn {
			if seen[dependency] || positions[dependency] >= positions[task.Role] ||
				registeredPosition(dependency) < 0 {
				return empty, errors.New("invalid, duplicate, missing or forward task dependency")
			}
			if _, found := positions[dependency]; !found {
				return empty, errors.New("unknown dependency")
			}
			seen[dependency] = true
		}
		switch task.Role {
		case "scout":
			if len(task.DependsOn) != 0 {
				return empty, errors.New("scout cannot depend on another specialist")
			}
		case "source":
			if len(task.DependsOn) != 1 || task.DependsOn[0] != "scout" {
				return empty, errors.New("source must depend on scout")
			}
		default:
			if !seen["source"] {
				return empty, errors.New("optional specialist must depend on source")
			}
		}
		if task.Status == "completed" || task.Status == "running" {
			for _, dependency := range task.DependsOn {
				if states[dependency] != "completed" {
					return empty, errors.New("running or completed task has unfinished dependency")
				}
			}
		}
	}
	hasFailure := false
	allCompleted := true
	for _, task := range req.Tasks {
		switch task.Status {
		case "running":
			empty.Running = append(empty.Running, task.Role)
		case "failed", "cancelled":
			hasFailure = true
		}
		if task.Status != "completed" {
			allCompleted = false
		}
	}
	if len(empty.Running) > req.MaxParallel {
		return empty, errors.New("stored tasks exceed allowed parallel execution")
	}
	if req.RunStatus == "approved" && (len(empty.Running) != 0 || hasFailure) {
		return empty, errors.New("approved review has inconsistent task states")
	}
	if req.RunStatus == "completed" && !allCompleted {
		return empty, errors.New("completed review has incomplete specialists")
	}
	if req.RunStatus == "planned" || req.RunStatus == "cancelled" ||
		req.RunStatus == "interrupted" || req.RunStatus == "failed" || hasFailure ||
		allCompleted {
		empty.Terminal = req.RunStatus != "planned"
		empty.Reason = req.RunStatus
		if hasFailure && req.RunStatus == "running" {
			empty.Reason = "failed"
			empty.Terminal = true
		}
		for _, task := range req.Tasks {
			if task.Status == "pending" {
				empty.Waiting = append(empty.Waiting, task.Role)
			}
		}
		return empty, nil
	}
	slots := req.MaxParallel - len(empty.Running)
	for _, task := range req.Tasks {
		if task.Status != "pending" {
			continue
		}
		ready := true
		for _, dependency := range task.DependsOn {
			ready = ready && states[dependency] == "completed"
		}
		if ready && slots > 0 {
			empty.Ready = append(empty.Ready, task.Role)
			slots--
		} else {
			empty.Waiting = append(empty.Waiting, task.Role)
		}
	}
	empty.Reason = "awaiting approved execution"
	return empty, nil
}

func runDispatch(input io.Reader, output io.Writer) error {
	dec := json.NewDecoder(io.LimitReader(input, 8193))
	dec.DisallowUnknownFields()
	var req dispatchRequest
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("invalid dispatch request: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("dispatch request must contain exactly one JSON object")
	}
	advice, err := decideDispatch(req)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(advice)
}
