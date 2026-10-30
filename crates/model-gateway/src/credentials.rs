//! Provider credentials. Tokens live only in the OS credential store (or, for
//! opt-in CI smoke tests, a process environment variable). They are never
//! written to SQLite, logs, reports, exports or the WebView.
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::ProviderError;

pub const KEYRING_SERVICE: &str = "codetwin-ml.model-gateway";

/// A secret string with a redacted `Debug` and best-effort wipe on drop.
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > 512 {
            return Err(ProviderError::Credential(
                "token must be 1..512 bytes".into(),
            ));
        }
        if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ProviderError::Credential(
                "token contains whitespace or control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A short non-reversible fingerprint for diagnostics (never the token).
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(self.0.as_bytes());
        d[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        bytes.iter_mut().for_each(|b| *b = 0);
        std::hint::black_box(&bytes);
    }
}

pub trait CredentialStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Secret>, ProviderError>;
    fn set(&self, account: &str, secret: &Secret) -> Result<(), ProviderError>;
    fn delete(&self, account: &str) -> Result<bool, ProviderError>;
    fn backend(&self) -> &'static str;
}

/// OS credential store: Windows Credential Manager, macOS Keychain, or the
/// freedesktop Secret Service on Linux (GNOME Keyring, KWallet), which
/// persists across restarts and reboots. There is no plaintext or
/// application-encrypted fallback: when the store is missing or locked every
/// operation fails closed and the operator is told how to recover.
pub struct KeyringStore;

/// Whether the OS credential store can be used right now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CredentialStoreStatus {
    pub backend: &'static str,
    /// Survives application restarts and machine reboots.
    pub persistent: bool,
    pub available: bool,
    /// What failed and how to recover; never contains a secret.
    pub guidance: Option<String>,
}

const PROBE_ACCOUNT: &str = "codetwin-ml.availability-probe";

fn store_error(action: &str, e: keyring::Error) -> ProviderError {
    let guidance = match &e {
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_)
            if cfg!(target_os = "linux") =>
        {
            " The Secret Service (GNOME Keyring, KWallet or another freedesktop              secret store) is not running or is locked. Unlock it (log in to the              desktop session, or run `gnome-keyring-daemon --unlock`), then re-enter              the key. CodeTwin does not store keys in plaintext."
        }
        keyring::Error::NoStorageAccess(_) => {
            " The OS credential store is locked or access was denied; unlock it and              re-enter the key."
        }
        _ => "",
    };
    // keyring errors describe the store, never the secret value.
    ProviderError::Credential(format!("credential {action} failed: {e}.{guidance}"))
}

impl KeyringStore {
    fn entry(account: &str) -> Result<keyring::Entry, ProviderError> {
        keyring::Entry::new(KEYRING_SERVICE, account).map_err(|e| store_error("store open", e))
    }

    /// Probe the store with a read of an entry that never holds a secret.
    pub fn status(&self) -> CredentialStoreStatus {
        let result = Self::entry(PROBE_ACCOUNT).and_then(|e| match e.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(store_error("read", e)),
        });
        CredentialStoreStatus {
            backend: self.backend(),
            persistent: true,
            available: result.is_ok(),
            guidance: result.err().map(|e| e.to_string()),
        }
    }
}

impl CredentialStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<Secret>, ProviderError> {
        match Self::entry(account)?.get_password() {
            Ok(value) => Secret::new(value).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(store_error("read", e)),
        }
    }
    fn set(&self, account: &str, secret: &Secret) -> Result<(), ProviderError> {
        Self::entry(account)?
            .set_password(secret.expose())
            .map_err(|e| store_error("write", e))
    }
    fn delete(&self, account: &str) -> Result<bool, ProviderError> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(store_error("delete", e)),
        }
    }
    fn backend(&self) -> &'static str {
        if cfg!(windows) {
            "windows_credential_manager"
        } else if cfg!(target_os = "macos") {
            "macos_keychain"
        } else {
            "linux_secret_service"
        }
    }
}

/// Read-only store backed by a process environment variable (opt-in CI).
pub struct EnvCredentialStore {
    pub variable: String,
}

impl CredentialStore for EnvCredentialStore {
    fn get(&self, _: &str) -> Result<Option<Secret>, ProviderError> {
        match std::env::var(&self.variable) {
            Ok(v) if !v.trim().is_empty() => Secret::new(v).map(Some),
            _ => Ok(None),
        }
    }
    fn set(&self, _: &str, _: &Secret) -> Result<(), ProviderError> {
        Err(ProviderError::Credential(
            "environment credentials are read-only".into(),
        ))
    }
    fn delete(&self, _: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::Credential(
            "environment credentials are read-only".into(),
        ))
    }
    fn backend(&self) -> &'static str {
        "environment"
    }
}

/// In-memory store for tests.
#[derive(Default)]
pub struct MemoryCredentialStore(Mutex<BTreeMap<String, String>>);

impl CredentialStore for MemoryCredentialStore {
    fn get(&self, account: &str) -> Result<Option<Secret>, ProviderError> {
        self.0
            .lock()
            .expect("mutex")
            .get(account)
            .map(|v| Secret::new(v.clone()))
            .transpose()
    }
    fn set(&self, account: &str, secret: &Secret) -> Result<(), ProviderError> {
        self.0
            .lock()
            .expect("mutex")
            .insert(account.into(), secret.expose().into());
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<bool, ProviderError> {
        Ok(self.0.lock().expect("mutex").remove(account).is_some())
    }
    fn backend(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_print() {
        let s = Secret::new("7|om_SyntheticTestValue").unwrap();
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.fingerprint().len(), 8);
        assert!(Secret::new("has space").is_err());
        assert!(Secret::new("").is_err());
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryCredentialStore::default();
        store
            .set("openmindai", &Secret::new("abc123").unwrap())
            .unwrap();
        assert_eq!(store.get("openmindai").unwrap().unwrap().expose(), "abc123");
        assert!(store.delete("openmindai").unwrap());
        assert!(store.get("openmindai").unwrap().is_none());
    }
}
