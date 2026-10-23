// Adapted from PentAGI backend/pkg/providers/subtask_patch.go.
// Copyright (c) 2025 PentAGI Development Team. Licensed under MIT.
// See ../../licenses/pentagi/LICENSE. CodeTwin replaces provider/SQL types
// and logging with a strict, dependency-free, local task-delta contract.
package refinement

import (
	"fmt"
	"slices"
)

type Subtask struct {
	ID          int64
	Title       string
	Description string
}
type Operation struct {
	Op          string
	ID          *int64
	AfterID     *int64
	Title       string
	Description string
}

// Apply uses the upstream two-pass algorithm: removals and modifications first,
// then additions and reorders. A failing operation leaves the caller's plan
// unchanged and returns no partial result.
func Apply(planned []Subtask, operations []Operation) ([]Subtask, error) {
	result := append([]Subtask(nil), planned...)
	if len(operations) > 8 || len(planned) > 6 {
		return nil, fmt.Errorf("task refinement limit exceeded")
	}
	seenIDs := make(map[int64]bool, len(result))
	for _, task := range result {
		if task.ID < 1 || seenIDs[task.ID] {
			return nil, fmt.Errorf("invalid duplicate task id")
		}
		seenIDs[task.ID] = true
	}
	removed := make(map[int64]bool)
	index := buildIndexMap(result)
	for i, op := range operations {
		switch op.Op {
		case "remove":
			if op.ID == nil || !seenIDs[*op.ID] || removed[*op.ID] {
				return nil, fmt.Errorf("operation %d: unknown or repeated removal", i)
			}
			removed[*op.ID] = true
		case "modify":
			if op.ID == nil || !seenIDs[*op.ID] || removed[*op.ID] ||
				(op.Title == "" && op.Description == "") {
				return nil, fmt.Errorf("operation %d: invalid modification", i)
			}
			if op.Title != "" {
				result[index[*op.ID]].Title = op.Title
			}
			if op.Description != "" {
				result[index[*op.ID]].Description = op.Description
			}
		case "add", "reorder":
			// Applied in the second pass once removals are known.
		default:
			return nil, fmt.Errorf("operation %d: unknown operation", i)
		}
	}
	if len(removed) > 0 {
		filtered := make([]Subtask, 0, len(result)-len(removed))
		for _, item := range result {
			if !removed[item.ID] {
				filtered = append(filtered, item)
			}
		}
		result = filtered
	}
	index = buildIndexMap(result)
	for i, op := range operations {
		switch op.Op {
		case "add":
			if op.ID == nil || *op.ID < 1 || op.Title == "" || op.Description == "" {
				return nil, fmt.Errorf("operation %d: incomplete addition", i)
			}
			if _, exists := index[*op.ID]; exists {
				return nil, fmt.Errorf("operation %d: duplicate task", i)
			}
			at, err := calculateInsertIndex(op.AfterID, index, len(result))
			if err != nil {
				return nil, fmt.Errorf("operation %d: %w", i, err)
			}
			result = slices.Insert(result, at, Subtask{
				ID: *op.ID, Title: op.Title, Description: op.Description,
			})
			index = buildIndexMap(result)
		case "reorder":
			if op.ID == nil {
				return nil, fmt.Errorf("operation %d: missing task to move", i)
			}
			old, ok := index[*op.ID]
			if !ok || (op.AfterID != nil && *op.AfterID == *op.ID) {
				return nil, fmt.Errorf("operation %d: invalid reorder", i)
			}
			item := result[old]
			result = slices.Delete(result, old, old+1)
			index = buildIndexMap(result)
			at, err := calculateInsertIndex(op.AfterID, index, len(result))
			if err != nil {
				return nil, fmt.Errorf("operation %d: %w", i, err)
			}
			result = slices.Insert(result, at, item)
			index = buildIndexMap(result)
		}
	}
	return result, nil
}

// ID -> index map, ported from the upstream subtask patch algorithm.
func buildIndexMap(subtasks []Subtask) map[int64]int {
	idToIdx := make(map[int64]int, len(subtasks))
	for i, st := range subtasks {
		if st.ID != 0 {
			idToIdx[st.ID] = i
		}
	}
	return idToIdx
}

// Position-aware insertion from the upstream algorithm. CodeTwin fails closed
// rather than appending if an after_id is stale or absent.
func calculateInsertIndex(afterID *int64, idToIdx map[int64]int, length int) (int, error) {
	if afterID == nil || *afterID == 0 {
		return 0, nil
	}
	if idx, ok := idToIdx[*afterID]; ok {
		return idx + 1, nil
	}
	return length, fmt.Errorf("missing insertion anchor")
}
