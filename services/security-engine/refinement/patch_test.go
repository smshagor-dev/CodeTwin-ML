package refinement

import "testing"

func pointer(value int64) *int64 { return &value }

func TestUpstreamTwoPassDeltaIsNonDestructive(t *testing.T) {
	original := []Subtask{{1, "a", "one"}, {2, "b", "two"}, {3, "c", "three"}}
	result, err := Apply(original, []Operation{
		{Op: "modify", ID: pointer(2), Description: "changed"},
		{Op: "remove", ID: pointer(1)},
		{Op: "add", ID: pointer(4), Title: "d", Description: "four", AfterID: pointer(2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 || result[0].Description != "changed" ||
		result[1].ID != 4 || result[2].ID != 3 {
		t.Fatalf("unexpected patch result: %#v", result)
	}
	if len(original) != 3 || original[0].ID != 1 || original[1].Description != "two" {
		t.Fatal("source changed in place")
	}
}
func TestReorderAndMissingAnchor(t *testing.T) {
	plan := []Subtask{{1, "a", "a"}, {2, "b", "b"}, {3, "c", "c"}}
	updated, err := Apply(plan, []Operation{{Op: "reorder", ID: pointer(3), AfterID: pointer(1)}})
	if err != nil || updated[1].ID != 3 {
		t.Fatalf("reorder %#v %v", updated, err)
	}
	if _, err := Apply(plan, []Operation{{Op: "add", ID: pointer(4), Title: "d",
		Description: "d", AfterID: pointer(99)}}); err == nil {
		t.Fatal("stale anchor was silently accepted")
	}
}
func TestInvalidPatchCannotReturnPartialState(t *testing.T) {
	plan := []Subtask{{1, "a", "a"}, {2, "b", "b"}}
	result, err := Apply(plan, []Operation{
		{Op: "remove", ID: pointer(1)},
		{Op: "add", ID: pointer(2), Title: "duplicate", Description: "invalid"},
	})
	if err == nil || result != nil || len(plan) != 2 {
		t.Fatal("invalid patch exposed a partial state")
	}
}
