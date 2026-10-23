package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSelectedSpecialistsRespectDependencyOrder(t *testing.T) {
	p, err := plan(request{ProtocolVersion: 1, Objective: "Review database migrations and runtime containers"})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, item := range p.Tasks {
		got = append(got, item.Role)
	}
	expected := "scout,source,database,runtime"
	if strings.Join(got, ",") != expected {
		t.Fatalf("got %v, expected %s", got, expected)
	}
	for _, item := range p.Tasks[2:] {
		if len(item.DependsOn) != 1 || item.DependsOn[0] != "source" {
			t.Fatalf("unsafe dependency: %#v", item)
		}
	}
}

func TestBroadObjectiveUsesOnlyRegisteredPassiveRoles(t *testing.T) {
	p, err := plan(request{ProtocolVersion: 1, Objective: "Review this project"})
	if err != nil || len(p.Tasks) != 6 {
		t.Fatalf("plan=%#v err=%v", p, err)
	}
}

func TestRejectUnexpectedOrOversizedRequests(t *testing.T) {
	for _, raw := range []string{
		`{"protocol_version":2,"objective":"audit"}`,
		`{"protocol_version":1,"objective":""}`,
		`{"protocol_version":1,"objective":"audit","command":"bash"}`,
		`{"protocol_version":1,"objective":"audit"}{"protocol_version":1,"objective":"again"}`,
		`{"protocol_version":1,"objective":"` + strings.Repeat("x", 2100) + `"}`,
	} {
		var out bytes.Buffer
		if err := run(strings.NewReader(raw), &out); err == nil {
			t.Fatalf("accepted %q", raw[:min(len(raw), 100)])
		}
		if out.Len() != 0 {
			t.Fatal("partial plan escaped on error")
		}
	}
}

func TestProtocolRoundtrip(t *testing.T) {
	var out bytes.Buffer
	if err := run(strings.NewReader(`{"protocol_version":1,"objective":"review secrets"}`), &out); err != nil {
		t.Fatal(err)
	}
	var p proposal
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 3 || p.Tasks[2].Role != "secrets" {
		t.Fatalf("unexpected tasks: %#v", p.Tasks)
	}
}

func TestPriorFailedSpecialistSuggestsFollowupWithoutRunningIt(t *testing.T) {
	p, err := plan(request{ProtocolVersion: 1, Objective: "Review test coverage", History: []memoryHint{
		{Role: "secrets", Status: "failed"},
		{Role: "runtime", Status: "completed"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{}
	for _, item := range p.Tasks {
		roles = append(roles, item.Role)
	}
	if strings.Join(roles, ",") != "scout,source,secrets,qa" {
		t.Fatalf("unexpected memory-informed plan: %v", roles)
	}
}

func TestHistoryIsStrictlyBoundedAndUsesRegisteredRoles(t *testing.T) {
	for _, invalid := range []request{
		{ProtocolVersion: 1, Objective: "Review", History: []memoryHint{{Role: "shell", Status: "failed"}}},
		{ProtocolVersion: 1, Objective: "Review", History: []memoryHint{{Role: "secrets", Status: "running"}}},
		{ProtocolVersion: 1, Objective: "Review", History: make([]memoryHint, 13)},
	} {
		if _, err := plan(invalid); err == nil {
			t.Fatal("unsafe memory input was accepted")
		}
	}
}
