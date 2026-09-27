use lsp_enrichment::{LanguageServerConfig, LanguageServerKind};
use rusqlite::{params, OptionalExtension};
use thiserror::Error;

use crate::Database;

const SETTINGS_SCOPE: &str = "application";
const SETTINGS_PREFIX: &str = "lsp.server.";

#[derive(Debug, Error)]
pub enum SemanticConfigError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid persisted language server configuration: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct LanguageServerConfigService<'a> {
    database: &'a Database,
}

impl<'a> LanguageServerConfigService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn set(&self, config: &LanguageServerConfig) -> Result<(), SemanticConfigError> {
        let key = config_key(config.kind);
        let mut persisted = config.clone();
        persisted.initialization_options = None;
        let value = serde_json::to_string(&persisted)?;
        self.database.connection().execute(
            "INSERT INTO settings(scope, key, value_json, updated_at) \
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP) \
             ON CONFLICT(scope, key) DO UPDATE SET \
               value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP",
            params![SETTINGS_SCOPE, key, value],
        )?;
        Ok(())
    }

    pub fn get(
        &self,
        kind: LanguageServerKind,
    ) -> Result<Option<LanguageServerConfig>, SemanticConfigError> {
        let value: Option<String> = self
            .database
            .connection()
            .query_row(
                "SELECT value_json FROM settings WHERE scope = ?1 AND key = ?2",
                params![SETTINGS_SCOPE, config_key(kind)],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    pub fn list(&self) -> Result<Vec<LanguageServerConfig>, SemanticConfigError> {
        let mut statement = self.database.connection().prepare(
            "SELECT value_json FROM settings \
             WHERE scope = ?1 AND key LIKE ?2 ESCAPE '\\' ORDER BY key",
        )?;
        let pattern = format!("{}%", SETTINGS_PREFIX.replace('_', "\\_"));
        let rows = statement.query_map(params![SETTINGS_SCOPE, pattern], |row| {
            row.get::<_, String>(0)
        })?;
        let mut configs = Vec::new();
        for row in rows {
            configs.push(serde_json::from_str(&row?)?);
        }
        Ok(configs)
    }

    pub fn remove(&self, kind: LanguageServerKind) -> Result<bool, SemanticConfigError> {
        let changed = self.database.connection().execute(
            "DELETE FROM settings WHERE scope = ?1 AND key = ?2",
            params![SETTINGS_SCOPE, config_key(kind)],
        )?;
        Ok(changed > 0)
    }
}

fn config_key(kind: LanguageServerKind) -> String {
    format!("{SETTINGS_PREFIX}{}", kind.as_str())
}

#[cfg(test)]
mod tests {
    use lsp_enrichment::{LanguageServerConfig, LanguageServerKind};
    use serde_json::json;

    use crate::Database;

    use super::LanguageServerConfigService;

    #[test]
    fn round_trips_server_configuration_without_project_discovery() {
        let database = Database::open_in_memory().expect("database");
        let service = LanguageServerConfigService::new(&database);
        let config = LanguageServerConfig {
            kind: LanguageServerKind::TypeScript,
            executable_path: "/opt/tools/typescript-language-server".into(),
            arguments: vec!["--stdio".into()],
            initialization_options: None,
            enabled: true,
        };
        service.set(&config).expect("set");
        assert_eq!(
            service
                .get(LanguageServerKind::TypeScript)
                .expect("get")
                .as_ref(),
            Some(&config)
        );
        assert_eq!(service.list().expect("list"), vec![config]);
        assert!(service
            .remove(LanguageServerKind::TypeScript)
            .expect("remove"));
    }

    #[test]
    fn strips_caller_supplied_initialization_options() {
        let database = Database::open_in_memory().expect("database");
        let service = LanguageServerConfigService::new(&database);
        let config = LanguageServerConfig {
            kind: LanguageServerKind::RustAnalyzer,
            executable_path: "/opt/tools/rust-analyzer".into(),
            arguments: Vec::new(),
            initialization_options: Some(json!({
                "cargo": {"buildScripts": {"enable": true}},
                "procMacro": {"enable": true}
            })),
            enabled: true,
        };
        service.set(&config).expect("set");
        let persisted = service
            .get(LanguageServerKind::RustAnalyzer)
            .expect("get")
            .expect("config");
        assert!(persisted.initialization_options.is_none());
    }
}
