//! Dependency inventory from lockfiles and OSV-based vulnerability matching.

pub mod jvm_dotnet;
pub mod manifest;
pub mod osv;

pub use manifest::{
    manifest_kind, parse_manifest, Dependency, Ecosystem, ManifestKind, ParsedManifest,
};
pub use osv::{
    affects, compare_versions, cvss3_base_score, summarize, Advisory, MatchBasis, OsvClient,
    OsvError, DEFAULT_OSV_API,
};

pub const ANALYZER_VERSION: &str = "dependency-audit-v1";
