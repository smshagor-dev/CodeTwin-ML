# Detached QA Execution Workspace

CodeTwin treats an analyzed repository as untrusted data. A future test executor must avoid using the live repository as a writable working tree. This module adds a bounded detached-input staging primitive without claiming that filesystem sandboxing is complete.

## What is implemented

`prepare_detached_workspace` accepts an already hash-pinned `ExecutionInputSnapshot` set and copies exactly those approved files into a newly created workspace outside the analyzed repository. The operation revalidates source size and SHA-256 before copying, preserves the approved relative paths under `inputs/`, marks copied inputs read-only, creates separate writable `artifacts/` and `temp/` directories, and verifies the copied hashes again before returning.

The workspace is bounded to at most the existing QA target limit and 64 MiB of copied input data. Symlinked source inputs, root escapes, stale snapshots, parents located inside the analyzed repository, copied-file mutation, and unsafe cleanup targets are rejected.

`verify_detached_workspace` can be called again before a future launch. It verifies workspace containment, copied-file regular-file status, SHA-256, byte size, read-only state, aggregate byte count, and the explicit `dependency_complete = false` truth marker.

`cleanup_detached_workspace` removes only a workspace whose canonical parent, source-root separation, and CodeTwin-generated directory-name prefix still match the recorded workspace. It deliberately refuses arbitrary recursive deletion targets.

## What is not implemented

This is not yet a runnable full-project snapshot. Only explicitly approved test inputs are copied. Imports, application source, package manifests, fixtures, generated assets, compiled dependencies, language runtime support files, and framework configuration are not automatically included. Therefore `dependency_complete` is always false.

The Windows executor is not switched to this workspace in this change. Running a process from a detached current directory alone would not stop the same Windows user token from opening or modifying the original repository by absolute path. Filesystem isolation therefore remains false.

A Windows restricted token is also not claimed yet. Microsoft restricted tokens can remove privileges, mark SIDs deny-only, or add restricting SIDs, but a safe CodeTwin design still needs an ACL/security-identity contract that proves the runner can read its required toolchain/dependencies and write only approved workspace locations while losing write authority over the source repository.

## Required next step

Before `filesystem_isolation` can become true, CodeTwin still needs a verified identity/ACL boundary, such as a dedicated restricted SID/AppContainer-style identity with explicitly granted access to the detached workspace and trusted toolchain plus denied/unavailable write access to the source repository. Network isolation is a separate remaining requirement and must stay false until enforced independently.
