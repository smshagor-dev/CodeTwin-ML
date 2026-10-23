package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func basicDispatch() dispatchRequest {
	return dispatchRequest{ProtocolVersion: 1, RunStatus: "approved", MaxParallel: 2, Tasks: []dispatchTask{
		{Role: "scout", Status: "pending", DependsOn: []string{}},
		{Role: "source", Status: "pending", DependsOn: []string{"scout"}},
		{Role: "secrets", Status: "pending", DependsOn: []string{"source"}},
		{Role: "qa", Status: "pending", DependsOn: []string{"source"}},
	}}
}
func TestDispatchFollowsApprovedDependencies(t *testing.T) {
	r := basicDispatch()
	a, err := decideDispatch(r)
	if err != nil || strings.Join(a.Ready, ",") != "scout" || a.Terminal {
		t.Fatalf("initial advice %#v, %v", a, err)
	}
	r.RunStatus = "running"
	r.Tasks[0].Status = "completed"
	a, err = decideDispatch(r)
	if err != nil || strings.Join(a.Ready, ",") != "source" {
		t.Fatalf("source advice %#v, %v", a, err)
	}
	r.Tasks[1].Status = "completed"
	a, err = decideDispatch(r)
	if err != nil || strings.Join(a.Ready, ",") != "secrets,qa" {
		t.Fatalf("parallel advice %#v, %v", a, err)
	}
	r.Tasks[2].Status = "running"
	a, err = decideDispatch(r)
	if err != nil || strings.Join(a.Ready, ",") != "qa" {
		t.Fatalf("remaining slot advice %#v, %v", a, err)
	}
	r.Tasks[2].Status = "completed"
	r.Tasks[3].Status = "completed"
	r.RunStatus = "completed"
	a, err = decideDispatch(r)
	if err != nil || !a.Terminal || len(a.Ready) != 0 {
		t.Fatalf("final advice %#v, %v", a, err)
	}
}
func TestDispatchRejectsImpossibleStatesAndToolEscalation(t *testing.T) {
	tests := []func(*dispatchRequest){
		func(r *dispatchRequest) { r.Tasks[2].Role = "bash" },
		func(r *dispatchRequest) { r.Tasks[2].DependsOn = []string{"qa"} },
		func(r *dispatchRequest) { r.Tasks[2].DependsOn = nil },
		func(r *dispatchRequest) { r.Tasks[3].Role = "secrets" },
		func(r *dispatchRequest) { r.Tasks[3].Status = "running" },
		func(r *dispatchRequest) { r.MaxParallel = 10 },
		func(r *dispatchRequest) { r.Tasks[1].Status = "completed" },
		func(r *dispatchRequest) { r.RunStatus = "completed" },
		func(r *dispatchRequest) { r.RunStatus = "unapproved" },
	}
	for i, mutate := range tests {
		r := basicDispatch()
		mutate(&r)
		if a, err := decideDispatch(r); err == nil {
			t.Fatalf("test %d allowed invalid dispatch %#v", i, a)
		}
	}
}
func TestCancelledAndFailedRunsNeverDispatch(t *testing.T) {
	for _, status := range []string{"planned", "failed", "cancelled", "interrupted"} {
		r := basicDispatch()
		r.RunStatus = status
		a, err := decideDispatch(r)
		if err != nil || len(a.Ready) > 0 {
			t.Fatalf("status %s: %#v %v", status, a, err)
		}
	}
	r := basicDispatch()
	r.RunStatus = "running"
	r.Tasks[0].Status = "failed"
	a, err := decideDispatch(r)
	if err != nil || !a.Terminal || len(a.Ready) > 0 {
		t.Fatalf("failed task dispatched: %#v %v", a, err)
	}
}
func TestDispatchWireRejectsUnknownFieldsAndMultipleObjects(t *testing.T) {
	for _, input := range []string{
		`{"protocol_version":1,"run_status":"approved","max_parallel":2,"tasks":[],"shell":"bash"}`,
		`{"protocol_version":1}` + `{"protocol_version":1}`,
		`{"protocol_version":1,"tasks":[],"max_parallel":7}`,
	} {
		var output bytes.Buffer
		if err := runDispatch(strings.NewReader(input), &output); err == nil || output.Len() > 0 {
			t.Fatalf("accepted %q", input)
		}
	}
	r := basicDispatch()
	encoded, _ := json.Marshal(r)
	var output bytes.Buffer
	if err := runDispatch(bytes.NewReader(encoded), &output); err != nil {
		t.Fatal(err)
	}
	var parsed dispatchAdvice
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil || len(parsed.Ready) != 1 {
		t.Fatalf("invalid roundtrip %#v %v", parsed, err)
	}
}
