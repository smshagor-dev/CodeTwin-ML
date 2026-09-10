# Source Indexing

The initial source indexer is a Rust service built on Tree-sitter. It parses supported source files without executing repository commands and returns deterministic AST metadata, SHA-256 content identity, parse state, and definition symbols with source ranges.

## Initial language adapters

- TypeScript and TSX
- JavaScript and JSX
- Python
- Rust
- Go
- C
- C++
- PHP

Each adapter uses an official Tree-sitter grammar package. TypeScript and TSX use a CodeTwin-owned definition query because the upstream grammar tag query does not cover all common production definition forms needed by the indexer. The other initial adapters use their grammar package tag queries. Tree-sitter provides syntax structure; future LSP adapters will augment it with compiler-quality cross-file resolution rather than replacing the parser.

## Incremental behavior

The indexer accepts a map of known file hashes. Files whose SHA-256 content hash has not changed are returned as unchanged and are not reparsed. The current desktop command performs a full first-pass index because persistent project snapshots are not wired to the SQLite file/symbol tables yet.

## Safety boundaries

The walker does not follow symbolic links and prunes common dependency/build/cache directories. Supported source files larger than 5 MiB are skipped with an explicit reason instead of being loaded blindly. Invalid UTF-8 and read/metadata failures also produce explicit skip reasons.

This subsystem does not run package scripts, test commands, compilers, language servers, or arbitrary repository commands. Execution remains unavailable until the sandbox policy engine exists.
