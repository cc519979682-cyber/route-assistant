use crate::error::{AppError, AppResult};
use crate::models::{
    AuthKind, ChangePlan, OperationHistoryItem, PluginKind, RouterProfile, RouterProfileInput,
};
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use keyring::Entry;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

const KEYRING_SERVICE: &str = "io.github.route-assistant.desktop";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialPayload {
    password: Option<String>,
    private_key_path: Option<String>,
    private_key_passphrase: Option<String>,
}

pub struct Store {
    connection: Mutex<Connection>,
    data_dir: PathBuf,
}

impl Store {
    pub fn open_default() -> AppResult<Self> {
        let dirs = ProjectDirs::from("io.github", "route-assistant", "Route Assistant")
            .ok_or_else(|| AppError::Storage("无法确定应用数据目录".into()))?;
        std::fs::create_dir_all(dirs.data_local_dir())
            .map_err(|error| AppError::Storage(error.to_string()))?;
        Self::open(dirs.data_local_dir().join("route-assistant.db"), dirs.data_local_dir())
    }

    pub fn open(path: impl AsRef<Path>, data_dir: impl AsRef<Path>) -> AppResult<Self> {
        let connection = Connection::open(path).map_err(|error| AppError::Storage(error.to_string()))?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS router_profiles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    auth_kind TEXT NOT NULL,
                    credential_ref TEXT NOT NULL,
                    host_key_fingerprint TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS change_plans (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    consumed_at TEXT,
                    FOREIGN KEY(profile_id) REFERENCES router_profiles(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS operation_history (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    plugin TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    backup_id TEXT,
                    success INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES router_profiles(id) ON DELETE CASCADE
                );
                "#,
            )
            .map_err(|error| AppError::Storage(error.to_string()))?;
        Ok(Self {
            connection: Mutex::new(connection),
            data_dir: data_dir.as_ref().to_path_buf(),
        })
    }

    fn db(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| AppError::Storage("本地数据库锁已损坏".into()))
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn save_profile(&self, input: &RouterProfileInput, fingerprint: &str) -> AppResult<RouterProfile> {
        let id = input.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
        let credential_ref = format!("router:{id}");
        let payload = CredentialPayload {
            password: input.password.clone(),
            private_key_path: input.private_key_path.clone(),
            private_key_passphrase: input.private_key_passphrase.clone(),
        };
        let secret = serde_json::to_string(&payload)
            .map_err(|error| AppError::Credential(error.to_string()))?;
        Entry::new(KEYRING_SERVICE, &credential_ref)
            .map_err(|error| AppError::Credential(error.to_string()))?
            .set_password(&secret)
            .map_err(|error| AppError::Credential(error.to_string()))?;

        let now = Utc::now().to_rfc3339();
        self.db()?
            .execute(
                r#"INSERT INTO router_profiles
                   (id, name, host, port, username, auth_kind, credential_ref, host_key_fingerprint, created_at, updated_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                   ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name, host=excluded.host, port=excluded.port,
                   username=excluded.username, auth_kind=excluded.auth_kind,
                   credential_ref=excluded.credential_ref,
                   host_key_fingerprint=excluded.host_key_fingerprint, updated_at=excluded.updated_at"#,
                params![
                    id,
                    input.name,
                    input.host,
                    input.port,
                    input.username,
                    auth_kind_to_db(&input.auth_kind),
                    credential_ref,
                    fingerprint,
                    now,
                ],
            )
            .map_err(|error| AppError::Storage(error.to_string()))?;

        Ok(RouterProfile {
            id,
            name: input.name.clone(),
            host: input.host.clone(),
            port: input.port,
            username: input.username.clone(),
            auth_kind: input.auth_kind.clone(),
            credential_ref,
            host_key_fingerprint: Some(fingerprint.to_owned()),
        })
    }

    pub fn list_profiles(&self) -> AppResult<Vec<RouterProfile>> {
        let connection = self.db()?;
        let mut statement = connection
            .prepare(
                "SELECT id,name,host,port,username,auth_kind,credential_ref,host_key_fingerprint FROM router_profiles ORDER BY updated_at DESC",
            )
            .map_err(|error| AppError::Storage(error.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                Ok(RouterProfile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    host: row.get(2)?,
                    port: row.get(3)?,
                    username: row.get(4)?,
                    auth_kind: auth_kind_from_db(row.get::<_, String>(5)?.as_str()),
                    credential_ref: row.get(6)?,
                    host_key_fingerprint: row.get(7)?,
                })
            })
            .map_err(|error| AppError::Storage(error.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppError::Storage(error.to_string()))
    }

    pub fn get_profile(&self, id: &str) -> AppResult<RouterProfile> {
        self.db()?
            .query_row(
                "SELECT id,name,host,port,username,auth_kind,credential_ref,host_key_fingerprint FROM router_profiles WHERE id=?1",
                [id],
                |row| {
                    Ok(RouterProfile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        host: row.get(2)?,
                        port: row.get(3)?,
                        username: row.get(4)?,
                        auth_kind: auth_kind_from_db(row.get::<_, String>(5)?.as_str()),
                        credential_ref: row.get(6)?,
                        host_key_fingerprint: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|error| AppError::Storage(error.to_string()))?
            .ok_or_else(|| AppError::Storage("找不到软路由档案".into()))
    }

    pub fn profile_input_with_secret(&self, profile: &RouterProfile) -> AppResult<RouterProfileInput> {
        let secret = Entry::new(KEYRING_SERVICE, &profile.credential_ref)
            .map_err(|error| AppError::Credential(error.to_string()))?
            .get_password()
            .map_err(|error| AppError::Credential(error.to_string()))?;
        let payload: CredentialPayload = serde_json::from_str(&secret)
            .map_err(|error| AppError::Credential(error.to_string()))?;
        Ok(RouterProfileInput {
            id: Some(profile.id.clone()),
            name: profile.name.clone(),
            host: profile.host.clone(),
            port: profile.port,
            username: profile.username.clone(),
            auth_kind: profile.auth_kind.clone(),
            password: payload.password,
            private_key_path: payload.private_key_path,
            private_key_passphrase: payload.private_key_passphrase,
            trust_host_key: true,
        })
    }

    pub fn save_plan(&self, plan: &ChangePlan) -> AppResult<()> {
        let payload = serde_json::to_string(plan).map_err(|error| AppError::Storage(error.to_string()))?;
        self.db()?
            .execute(
                "INSERT INTO change_plans (id,profile_id,payload,created_at) VALUES (?1,?2,?3,?4)",
                params![plan.id, plan.profile_id, payload, Utc::now().to_rfc3339()],
            )
            .map_err(|error| AppError::Storage(error.to_string()))?;
        Ok(())
    }

    pub fn get_plan(&self, id: &str) -> AppResult<ChangePlan> {
        let payload: String = self
            .db()?
            .query_row(
                "SELECT payload FROM change_plans WHERE id=?1 AND consumed_at IS NULL",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| AppError::Storage(error.to_string()))?
            .ok_or_else(|| AppError::Storage("变更预览已失效，请重新生成".into()))?;
        serde_json::from_str(&payload).map_err(|error| AppError::Storage(error.to_string()))
    }

    pub fn consume_plan(&self, id: &str) -> AppResult<()> {
        self.db()?
            .execute(
                "UPDATE change_plans SET consumed_at=?2 WHERE id=?1",
                params![id, Utc::now().to_rfc3339()],
            )
            .map_err(|error| AppError::Storage(error.to_string()))?;
        Ok(())
    }

    pub fn add_history(&self, item: &OperationHistoryItem) -> AppResult<()> {
        self.db()?
            .execute(
                "INSERT INTO operation_history (id,profile_id,plugin,operation,summary,backup_id,success,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    item.id,
                    item.profile_id,
                    plugin_to_db(&item.plugin),
                    item.operation,
                    item.summary,
                    item.backup_id,
                    item.success,
                    item.created_at.to_rfc3339(),
                ],
            )
            .map_err(|error| AppError::Storage(error.to_string()))?;
        Ok(())
    }

    pub fn list_history(&self, profile_id: Option<&str>) -> AppResult<Vec<OperationHistoryItem>> {
        let connection = self.db()?;
        let sql = if profile_id.is_some() {
            "SELECT id,profile_id,plugin,operation,summary,backup_id,success,created_at FROM operation_history WHERE profile_id=?1 ORDER BY created_at DESC LIMIT 100"
        } else {
            "SELECT id,profile_id,plugin,operation,summary,backup_id,success,created_at FROM operation_history ORDER BY created_at DESC LIMIT 100"
        };
        let mut statement = connection.prepare(sql).map_err(|error| AppError::Storage(error.to_string()))?;
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<OperationHistoryItem> {
            let created: String = row.get(7)?;
            Ok(OperationHistoryItem {
                id: row.get(0)?,
                profile_id: row.get(1)?,
                plugin: plugin_from_db(row.get::<_, String>(2)?.as_str()),
                operation: row.get(3)?,
                summary: row.get(4)?,
                backup_id: row.get(5)?,
                success: row.get(6)?,
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        };
        let rows = if let Some(profile_id) = profile_id {
            statement.query_map([profile_id], mapper)
        } else {
            statement.query_map([], mapper)
        }
        .map_err(|error| AppError::Storage(error.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppError::Storage(error.to_string()))
    }
}

fn auth_kind_to_db(kind: &AuthKind) -> &'static str {
    match kind {
        AuthKind::Password => "password",
        AuthKind::PrivateKey => "private_key",
    }
}

fn auth_kind_from_db(value: &str) -> AuthKind {
    if value == "private_key" {
        AuthKind::PrivateKey
    } else {
        AuthKind::Password
    }
}

fn plugin_to_db(kind: &PluginKind) -> &'static str {
    match kind {
        PluginKind::OpenClash => "openclash",
        PluginKind::Nikki => "nikki",
        PluginKind::Unsupported => "unsupported",
    }
}

fn plugin_from_db(value: &str) -> PluginKind {
    match value {
        "openclash" => PluginKind::OpenClash,
        "nikki" => PluginKind::Nikki,
        _ => PluginKind::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_database_schema() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().join("test.db"), directory.path()).unwrap();
        assert!(store.list_profiles().unwrap().is_empty());
    }
}

