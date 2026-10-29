//! Persisted web search provider settings (one row). The API key is kept in
//! the OS credential store by the desktop, never here.
use research_retrieval::search::{request_url, SearchConfig, SearchProviderKind};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::Database;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchProviderRecord {
    pub config: SearchConfig,
    pub enabled: bool,
    pub updated_ms: i64,
}

pub struct SearchSettings<'a> {
    db: &'a Database,
}

impl<'a> SearchSettings<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn get(&self) -> Result<Option<SearchProviderRecord>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT kind, base_url, enabled, max_results, updated_ms FROM search_provider_settings WHERE id=1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?
            .map(|(kind, base_url, enabled, max_results, updated_ms)| {
                Ok(SearchProviderRecord {
                    config: SearchConfig {
                        kind: SearchProviderKind::parse(&kind).ok_or("unknown search provider")?,
                        base_url,
                        max_results: max_results.clamp(1, 10) as usize,
                    },
                    enabled: enabled != 0,
                    updated_ms,
                })
            })
            .transpose()
    }

    /// Validate and save. Search endpoints must be public HTTPS (the same
    /// SSRF policy as research retrieval applies at request time).
    pub fn save(
        &self,
        kind: &str,
        base_url: &str,
        enabled: bool,
        max_results: usize,
    ) -> Result<SearchProviderRecord, String> {
        let kind = SearchProviderKind::parse(kind).ok_or("provider must be brave or searxng")?;
        let base_url = base_url.trim().trim_end_matches('/').to_owned();
        if !base_url.starts_with("https://") {
            return Err("search provider URL must use HTTPS".into());
        }
        let config = SearchConfig {
            kind,
            base_url: base_url.clone(),
            max_results: max_results.clamp(1, 10),
        };
        request_url(&config, "probe").map_err(|e| e.to_string())?;
        self.db
            .connection()
            .execute(
                "INSERT INTO search_provider_settings(id,kind,base_url,enabled,max_results,updated_ms)
                 VALUES (1,?1,?2,?3,?4,?5)
                 ON CONFLICT(id) DO UPDATE SET kind=?1, base_url=?2, enabled=?3, max_results=?4, updated_ms=?5",
                params![
                    kind.as_str(),
                    base_url,
                    i64::from(enabled),
                    config.max_results as i64,
                    crate::collaboration::now_ms()
                ],
            )
            .map_err(|e| e.to_string())?;
        self.get()?.ok_or_else(|| "search settings not saved".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("s.sqlite3")).unwrap();
        let s = SearchSettings::new(&db);
        assert!(s.get().unwrap().is_none());
        assert!(s.save("brave", "http://api.search.brave.com", true, 5).is_err());
        assert!(s.save("google", "https://x.example", true, 5).is_err());
        let r = s.save("brave", "https://api.search.brave.com/", true, 50).unwrap();
        assert_eq!(r.config.max_results, 10);
        assert_eq!(r.config.base_url, "https://api.search.brave.com");
        assert!(r.enabled);
    }
}
