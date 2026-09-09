# Software Digital Twin

The foundation migration creates durable tables for projects, analysis runs, files, symbols, graph nodes, graph edges, normalized findings, evidence, artifacts, and settings. Graph edges are typed by a `relationship` field and indexed in both directions.

Future indexers will populate these entities incrementally using file content hashes, analyzer versions, Git commit identity, and project configuration. The UI will query bounded neighborhoods rather than rendering an entire repository graph.
