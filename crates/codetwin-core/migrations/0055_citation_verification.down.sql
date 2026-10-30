-- Reverts 0055. Sources and citations recorded before it are kept.
DROP TABLE research_reports;
DROP TABLE research_link_checks;
DROP TABLE citation_verifications;
DROP TABLE research_citation_claims;
DROP TABLE research_claims;
DROP TABLE research_source_text;
DROP INDEX idx_research_sources_canonical;
ALTER TABLE research_sources DROP COLUMN duplicate_of;
ALTER TABLE research_sources DROP COLUMN provenance_json;
ALTER TABLE research_sources DROP COLUMN published_ms;
ALTER TABLE research_sources DROP COLUMN metadata_json;
ALTER TABLE research_sources DROP COLUMN origin;
ALTER TABLE research_sources DROP COLUMN canonical_url;
