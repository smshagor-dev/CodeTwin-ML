# Source Indexing

The source indexer is a Rust service built on Tree-sitter. It parses supported source files without executing repository commands and returns deterministic AST metadata, SHA-256 content identity, parse state, definition symbols with source ranges, and import observations where supported.

## Initial language adapters

- TypeScript and TSX
- JavaScript and JSX
- Python
- Rust
- Go
- C
- C++
- PHP
- Java (symbols from the grammar tag query; `import`, wildcard and `import static` observations)

Each adapter uses an official Tree-sitter grammar package. TypeScript and TSX use a CodeTwin-owned definition query because the upstream grammar tag query does not cover all common production definition forms needed by the indexer. The other initial adapters use their grammar package tag queries. Tree-sitter provides syntax structure; future semantic/LSP adapters may augment it with compiler-quality cross-file resolution rather than replacing the parser.

## Persistent incremental behavior

`ProjectIndexService` wires the parser to SQLite. It derives stable project/file/symbol identities, compares persisted content hashes, skips reparsing unchanged files, updates changed files transactionally, and marks deleted files plus stale symbols/graph records inactive. Each source-index run persists analyzer/query/config identity and a detailed delta for added, modified, unchanged, deleted, skipped, and parse-error outcomes.

The indexer also records import observations. Conservative local resolution currently supports evidenced local TypeScript/JavaScript relative imports. External, unresolved, or unsupported imports remain observations and are not converted into local graph edges.

## Query and analysis consumers

The persisted index powers bounded file search, symbol search, graph neighborhoods, dependency/dependent queries, index history, and evidence-backed file impact analysis. Impact analysis follows only persisted `resolved_local` imports and does not infer call relationships or runtime behavior.

## Safety boundaries

The walker does not follow symbolic links and prunes common dependency/build/cache directories. Supported source files larger than 5 MiB are skipped with an explicit reason instead of being loaded blindly. Invalid UTF-8 and read/metadata failures also produce explicit skip reasons.

This subsystem does not run package scripts, test commands, compilers, language servers, or arbitrary repository commands. Execution remains unavailable until a separate sandbox and approval policy subsystem is implemented.
