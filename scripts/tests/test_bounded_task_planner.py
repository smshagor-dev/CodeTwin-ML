"""Regression tests for the bounded, non-executing task planner."""
import unittest

from scripts.bounded_task_planner import PlanRejected, Task, build_plan


class BoundedPlannerTests(unittest.TestCase):
    def test_deterministic_parallel_levels(self):
        plan = build_plan("project-1", [
            Task("review", "evidence_review", "Review", ("index", "scan")),
            Task("scan", "static_analysis", "Analyze"),
            Task("index", "source_index", "Index"),
        ])
        self.assertEqual([[t.task_id for t in level] for level in plan.levels], [
            ["index", "scan"], ["review"],
        ])
        self.assertFalse(plan.requires_approval)

    def test_active_requires_explicit_true(self):
        task = [Task("test", "web_security_test", "Authorized test")]
        for approval in (None, {}, {"web_security_test": False}, {"web_security_test": 1}):
            with self.subTest(approval=approval), self.assertRaises(PlanRejected):
                build_plan("p", task, approved_capabilities=approval)
        plan = build_plan("p", task, approved_capabilities={"web_security_test": True})
        self.assertTrue(plan.requires_approval)

    def test_unknown_capability_rejected(self):
        with self.assertRaises(PlanRejected):
            build_plan("p", [Task("t", "network_scan", "Not permitted")])

    def test_unhashable_capability_rejected(self):
        with self.assertRaises(PlanRejected):
            build_plan("p", [Task("t", ["source_index"], "Invalid")])

    def test_cycle_and_unknown_dependency_rejected(self):
        for tasks in (
            [Task("a", "static_analysis", "A", ("b",)), Task("b", "source_index", "B", ("a",))],
            [Task("a", "static_analysis", "A", ("missing",))],
        ):
            with self.subTest(tasks=tasks), self.assertRaises(PlanRejected):
                build_plan("p", tasks)

    def test_duplicate_ids_and_excessive_tasks_rejected(self):
        with self.assertRaises(PlanRejected):
            build_plan("p", [Task("x", "source_index", "A"), Task("x", "static_analysis", "B")])
        with self.assertRaises(PlanRejected):
            build_plan("p", [Task(f"t{i}", "source_index", "A") for i in range(33)])

    def test_malformed_inputs_fail_closed(self):
        for tasks in ([], "invalid", [object()], [Task("bad id", "source_index", "A")],
                      [Task("ok", "source_index", "")],
                      [Task("ok", "source_index", "A", ("x", "x"))]):
            with self.subTest(tasks=tasks), self.assertRaises(PlanRejected):
                build_plan("p", tasks)


if __name__ == "__main__":
    unittest.main()
