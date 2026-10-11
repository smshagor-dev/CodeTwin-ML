# Local Git review

Projects → Git changes → Load Git changes reads the registered project's repository root. Refresh re-reads the current working tree; the displayed patch is a review snapshot, not an approval token for a later commit.

The first Git workflow increment exposes branch/HEAD, changed paths, staged patches, working-tree patches, renamed paths and bounded untracked text previews. Empty repositories, detached HEAD, binary files, missing Git, conflicts and inaccessible repositories have explicit states. A nested indexed project must be registered at its repository root before Git review; parent repository changes are not silently substituted.

Native commands resolve the root from the project ID in SQLite, release the database lock and run on a blocking worker. No network, Git index writes, staging, commits, push or PR creation occur. Global/system configuration and inherited repository overrides are excluded. Git ownership checks stay enabled. External diff, textconv, fsmonitor and configured clean/process filters are disabled; filtered repositories therefore show raw working-tree content rather than executing project-supplied transformations. Submodules show Gitlink pointer changes; nested working-tree dirtiness is deliberately excluded to avoid invoking helpers configured only in nested repositories. Paths use Git's NUL-delimited porcelain status and literal pathspecs.

Each Git command has a 15-second timeout and 2 MiB output limit; status is limited to 500 changed paths. Untracked previews are limited to 256 KiB and UTF-8 regular files. Symlink content is not previewed. Non-UTF-8 paths fail explicitly rather than displaying an ambiguous lossy path. Git configuration and filesystem contents may still change between reads; mutations will require fresh evidence and an explicit review step when added.

Validation uses actual temporary Git repositories for index/HEAD preservation, staged vs working-tree patches, literal wildcard filenames, renames, unborn/detached branches, binary/oversized files and disabled external helpers. Production browser checks use fixture IPC for UI behavior, request cancellation, escaped content and responsive layout. They do not replace native desktop GUI validation.

Next increment: branch creation and selected-change commits with stale-review checks, preservation of unrelated staging, and an explicit publish/PR integration backed by the desktop user's own GitHub authentication.
