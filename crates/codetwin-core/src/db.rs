use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;

const MIGRATION_0001: &str = include_str!("../migrations/0001_initial.sql");

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self { connection };
        database.migrate()?;
        Ok(database)
    }

    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self { connection };
        database.migrate()?;
        Ok(database)
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    fn migrate(&self) -> Result<(), DatabaseError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);",
        )?;

        let applied: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 1)",
            [],
            |row| row.get(0),
        )?;

        if !applied {
            let tx = self.connection.unchecked_transaction()?;
            tx.execute_batch(MIGRATION_0001)?;
            tx.execute("INSERT INTO schema_migrations(version) VALUES (1)", [])?;
            tx.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Database;

    #[test]
    fn creates_expected_foundation_tables() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projects','analysis_runs','findings','graph_nodes','graph_edges')",
                [],
                |row| row.get(0),
            )
            .expect("query tables");
        assert_eq!(count, 5);
    }

    #[test]
    fn migration_is_idempotent() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=1",
                [],
                |row| row.get(0),
            )
            .expect("query migration");
        assert_eq!(count, 1);
    }
}
