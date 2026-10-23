package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAdaptiveFollowupNarrowsFailedSpecialists(t *testing.T) {
	out, err := planFollowup(followupRequest{
		ProtocolVersion: 1, RunStatus: "failed",
		Tasks: []followupTask{
			{"scout", "completed"}, {"source", "completed"},
			{"secrets", "completed"}, {"qa", "failed"}, {"database", "skipped"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Suggested || out.Proposal == nil || len(out.Proposal.Tasks) != 4 {
		t.Fatalf("missing scoped follow-up: %#v", out)
	}
	if out.Proposal.Tasks[2].Role != "qa" || out.Proposal.Tasks[3].Role != "database" {
		t.Fatalf("expanded or omitted approved roles: %#v", out.Proposal)
	}
}

func TestFollowupDoesNotBypassSourceEvidence(t *testing.T) {
	out, err := planFollowup(followupRequest{
		ProtocolVersion: 1, RunStatus: "interrupted",
		Tasks: []followupTask{
			{"scout", "completed"}, {"source", "interrupted"}, {"runtime", "cancelled"},
		},
	})
	if err != nil || !out.Suggested || len(out.Proposal.Tasks) != 2 {
		t.Fatalf("unsafe downstream follow-up: %#v %v", out, err)
	}
}

func TestFollowupRefusesUnneededAndInvalidScope(t *testing.T) {
	out, err := planFollowup(followupRequest{
		ProtocolVersion: 1, RunStatus: "failed",
		Tasks: []followupTask{
			{"scout", "completed"}, {"source", "completed"}, {"qa", "completed"},
		},
	})
	if err != nil || out.Suggested {
		t.Fatalf("unexpected duplicate follow-up: %#v %v", out, err)
	}
	for _, req := range []followupRequest{
		{ProtocolVersion: 1, RunStatus: "running", Tasks: []followupTask{{"scout", "completed"}, {"source", "failed"}}},
		{ProtocolVersion: 1, RunStatus: "failed", Tasks: []followupTask{{"scout", "completed"}, {"source", "running"}}},
		{ProtocolVersion: 1, RunStatus: "failed", Tasks: []followupTask{{"scout", "completed"}, {"source", "completed"}, {"bash", "skipped"}}},
		{ProtocolVersion: 1, RunStatus: "failed", Tasks: []followupTask{{"scout", "completed"}, {"source", "completed"}, {"qa", "skipped"}, {"secrets", "skipped"}}},
	} {
		if _, err := planFollowup(req); err == nil {
			t.Fatalf("unsafe history accepted: %#v", req)
		}
	}
}

func TestFollowupStrictJSONAndNoSourceDetails(t *testing.T) {
	req := followupRequest{ProtocolVersion: 1, RunStatus: "failed",
		Tasks: []followupTask{{"scout", "completed"}, {"source", "failed"}}}
	payload, _ := json.Marshal(req)
	var output bytes.Buffer
	if err := runFollowup(bytes.NewReader(payload), &output); err != nil {
		t.Fatal(err)
	}
	var out followupAdvice
	if err := json.Unmarshal(output.Bytes(), &out); err != nil || !out.Suggested {
		t.Fatalf("invalid protocol response: %#v %v", out, err)
	}
	for _, malformed := range []string{
		string(payload) + string(payload),
		`{"protocol_version":1,"run_status":"failed","tasks":[],"source":"private"}`,
		strings.Repeat("x", 4300),
	} {
		output.Reset()
		if err := runFollowup(strings.NewReader(malformed), &output); err == nil || output.Len() != 0 {
			t.Fatal("untrusted input reached follow-up planner")
		}
	}
}
