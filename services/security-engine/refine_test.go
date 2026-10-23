package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func baseRefinementPlan() proposal {
	return proposal{Tasks: []task{
		{Role: "scout", Objective: "Inventory indexed project", DependsOn: []string{}},
		{Role: "source", Objective: "Review indexed source", DependsOn: []string{"scout"}},
		{Role: "qa", Objective: "Assess QA evidence", DependsOn: []string{"source"}},
		{Role: "runtime", Objective: "Review runtime posture", DependsOn: []string{"source"}},
	}, Rationale: "Reviewed passive specialist task plan"}
}

func TestRefineAddModifyRemoveAndRequireSeparateApproval(t *testing.T) {
	p, err := refinePlan(refineRequest{
		ProtocolVersion: 1, Current: baseRefinementPlan(),
		Operations: []refineOp{
			{Op: "modify", Role: "qa", Objective: "Review all test coverage"},
			{Op: "remove", Role: "runtime"},
			{Op: "add", Role: "database", Objective: "Inspect the indexed schema"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{p.Tasks[0].Role, p.Tasks[1].Role, p.Tasks[2].Role, p.Tasks[3].Role}; strings.Join(got, ",") != "scout,source,qa,database" {
		t.Fatalf("unexpected specialist selection: %v", got)
	}
	if p.Tasks[2].Objective != "Review all test coverage" ||
		p.Tasks[3].DependsOn[0] != "source" {
		t.Fatalf("refined plan did not preserve dependency gate: %#v", p)
	}
}
func TestRefinementRejectsUnapprovedAndAmbiguousOperations(t *testing.T) {
	for _, ops := range [][]refineOp{
		{{Op: "remove", Role: "scout"}},
		{{Op: "modify", Role: "source", Objective: "Bypass"}},
		{{Op: "add", Role: "shell", Objective: "Execute network scan"}},
		{{Op: "reorder", Role: "qa", AfterRole: "runtime"}},
		{{Op: "remove", Role: "database"}},
		{{Op: "modify", Role: "qa", Objective: ""}},
		{{Op: "add", Role: "qa", Objective: "Duplicate"}},
		{{Op: "remove", Role: "qa"}, {Op: "modify", Role: "qa", Objective: "Race"}},
	} {
		if _, err := refinePlan(refineRequest{
			ProtocolVersion: 1, Current: baseRefinementPlan(), Operations: ops,
		}); err == nil {
			t.Fatalf("unsafe operation accepted: %#v", ops)
		}
	}
}
func TestRefinementCannotLeaveDanglingDependencies(t *testing.T) {
	p := baseRefinementPlan()
	p.Tasks[3].DependsOn = []string{"source", "qa"}
	if _, err := refinePlan(refineRequest{
		ProtocolVersion: 1, Current: p,
		Operations: []refineOp{{Op: "remove", Role: "qa"}},
	}); err == nil {
		t.Fatal("removing a required dependency was accepted")
	}
}
func TestRefineProtocolStrictAndRoundTrips(t *testing.T) {
	req := refineRequest{ProtocolVersion: 1, Current: baseRefinementPlan(),
		Operations: []refineOp{{Op: "remove", Role: "qa"}}}
	payload, _ := json.Marshal(req)
	var output bytes.Buffer
	if err := runRefine(bytes.NewReader(payload), &output); err != nil {
		t.Fatal(err)
	}
	var result proposal
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tasks) != 3 {
		t.Fatalf("unexpected plan size: %d", len(result.Tasks))
	}
	for _, input := range []string{
		string(payload) + string(payload),
		`{"protocol_version":1,"current":{},"operations":[],"shell":"bash"}`,
		`{"protocol_version":2,"current":{},"operations":[]}`,
		strings.Repeat("x", 8300),
	} {
		output.Reset()
		if err := runRefine(strings.NewReader(input), &output); err == nil || output.Len() > 0 {
			t.Fatal("accepted malformed request or emitted partial proposal")
		}
	}
}
