# Upstream code notice

The task-delta algorithm in `../../refinement/patch.go` is adapted from
`backend/pkg/providers/subtask_patch.go` in the PentAGI source project,
copyright (c) 2025 PentAGI Development Team.

The original source is MIT licensed; the unchanged upstream license text is
retained in `LICENSE`. Only the two-pass algorithm and index/insertion helpers
are adapted. CodeTwin replaces PentAGI database types, logging and provider
dependencies with a small, fully offline Go contract. CodeTwin does **not**
vendor or claim to integrate the complete PentAGI backend here.

Original repository: https://github.com/vxcontrol/pentagi
Original file: https://github.com/vxcontrol/pentagi/blob/main/backend/pkg/providers/subtask_patch.go
