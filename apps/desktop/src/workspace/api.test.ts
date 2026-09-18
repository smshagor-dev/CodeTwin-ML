import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());
const openMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: openMock }));

import { chooseProjectFolder, importProjectPath, validateWebsiteUrl } from "./api";
import type { AppPreferences } from "./types";

const basePreferences: AppPreferences = {
  display_name: "Local User",
  theme: "system",
  auto_run_security_on_import: false,
  auto_discover_tests_on_import: false,
};

describe("workspace API workflows", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openMock.mockReset();
  });

  it("handles native folder selection and cancellation without indexing", async () => {
    openMock.mockResolvedValueOnce(null);
    await expect(chooseProjectFolder()).resolves.toBeNull();

    openMock.mockResolvedValueOnce("/work/project");
    await expect(chooseProjectFolder()).resolves.toBe("/work/project");
    expect(openMock).toHaveBeenLastCalledWith(expect.objectContaining({
      directory: true,
      multiple: false,
    }));
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("validates website URLs before persistence", () => {
    expect(validateWebsiteUrl("")).toMatch(/Enter a website URL/);
    expect(validateWebsiteUrl("example.com")).toMatch(/absolute URL/);
    expect(validateWebsiteUrl("file:///tmp/test.html")).toMatch(/Only http/);
    expect(validateWebsiteUrl("https://user:pass@example.com")).toMatch(/credentials/);
    expect(validateWebsiteUrl("https://example.com/path")).toBeNull();
  });

  it("uses discovery and the existing persistent indexer in sequence", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "discover_project") return {
        languages: ["TypeScript"],
        frameworks: [],
        package_managers: [],
        build_systems: [],
        test_frameworks: ["Vitest"],
        databases: [],
        ci_providers: [],
        project_kinds: ["application"],
      };
      if (command === "index_project") return {
        project_id: "project-1",
        run_id: "run-1",
        status: "completed",
        delta: {
          files_scanned: 12,
          files_added: 12,
          files_modified: 0,
          files_unchanged: 0,
          files_deleted: 0,
          symbols_added: 44,
          symbols_updated: 0,
          symbols_removed: 0,
          parse_errors: 0,
          skipped_files: 0,
        },
        graph_node_count: 56,
        graph_edge_count: 24,
        duration_ms: 20,
      };
      throw new Error("unexpected command " + command);
    });

    const stages: string[] = [];
    const result = await importProjectPath("/work/repo", basePreferences, (stage) => stages.push(stage));

    expect(result.index.project_id).toBe("project-1");
    expect(result.postImportErrors).toEqual([]);
    expect(invokeMock.mock.calls.map((call) => call[0])).toEqual(["discover_project", "index_project"]);
    expect(stages).toEqual(["discovering", "indexing"]);
  });

  it("stops cleanly when project discovery fails", async () => {
    invokeMock.mockRejectedValueOnce(new Error("invalid project folder"));
    await expect(importProjectPath("/bad/project", basePreferences)).rejects.toThrow("invalid project folder");
    expect(invokeMock.mock.calls.map((call) => call[0])).toEqual(["discover_project"]);
  });

  it("keeps a successful index when optional post-import analysis fails", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "discover_project") return {
        languages: [], frameworks: [], package_managers: [], build_systems: [],
        test_frameworks: [], databases: [], ci_providers: [], project_kinds: [],
      };
      if (command === "index_project") return {
        project_id: "project-post-import",
        run_id: "run-post-import",
        status: "completed",
        delta: {
          files_scanned: 2, files_added: 2, files_modified: 0, files_unchanged: 0,
          files_deleted: 0, symbols_added: 2, symbols_updated: 0, symbols_removed: 0,
          parse_errors: 0, skipped_files: 0,
        },
        graph_node_count: 4,
        graph_edge_count: 1,
        duration_ms: 5,
      };
      if (command === "run_security_analysis") throw new Error("security unavailable");
      throw new Error("unexpected command " + command);
    });

    const result = await importProjectPath("/work/repo", {
      ...basePreferences,
      auto_run_security_on_import: true,
    });

    expect(result.index.project_id).toBe("project-post-import");
    expect(result.postImportErrors).toHaveLength(1);
    expect(result.postImportErrors[0]).toMatch(/security analysis/);
  });

  it("runs only explicitly enabled post-import analysis", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "discover_project") return {
        languages: [],
        frameworks: [],
        package_managers: [],
        build_systems: [],
        test_frameworks: [],
        databases: [],
        ci_providers: [],
        project_kinds: [],
      };
      if (command === "index_project") return {
        project_id: "project-2",
        run_id: "run-2",
        status: "completed",
        delta: {
          files_scanned: 1,
          files_added: 1,
          files_modified: 0,
          files_unchanged: 0,
          files_deleted: 0,
          symbols_added: 1,
          symbols_updated: 0,
          symbols_removed: 0,
          parse_errors: 0,
          skipped_files: 0,
        },
        graph_node_count: 2,
        graph_edge_count: 0,
        duration_ms: 4,
      };
      if (command === "run_security_analysis" || command === "run_qa_discovery") return {};
      throw new Error("unexpected command " + command);
    });

    const result = await importProjectPath("/work/repo", {
      ...basePreferences,
      auto_run_security_on_import: true,
      auto_discover_tests_on_import: true,
    });

    expect(result.postImportErrors).toEqual([]);
    expect(invokeMock.mock.calls.map((call) => call[0])).toEqual([
      "discover_project",
      "index_project",
      "run_security_analysis",
      "run_qa_discovery",
    ]);
  });
});
