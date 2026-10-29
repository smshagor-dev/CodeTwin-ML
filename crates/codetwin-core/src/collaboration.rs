//! Optional multi-user collaboration: principals, project roles, scoped
//! invitations, comment threads with revision history, separation of duties
//! for approvals, and a general audit log.
//!
//! Offline single-user use is unchanged: until a project turns on
//! `enforce_rbac`, every human principal acts as that project's
//! administrator. Automation principals (API tokens) never get an implicit
//! role and can never approve.
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::Database;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 256 bits from the OS CSPRNG, hex encoded.
pub fn random_secret() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "secure random generator unavailable".to_owned())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn new_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        &random_secret().unwrap_or_else(|_| sha256_hex(format!("{:?}", std::time::Instant::now()).as_bytes()))[..24]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Analyst,
    Approver,
    Administrator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Approver => "approver",
            Self::Administrator => "administrator",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "viewer" => Ok(Self::Viewer),
            "analyst" => Ok(Self::Analyst),
            "approver" => Ok(Self::Approver),
            "administrator" => Ok(Self::Administrator),
            other => Err(format!("unknown role `{other}`")),
        }
    }

    pub fn allows(self, action: Action) -> bool {
        use Action as A;
        match action {
            A::View => true,
            A::Comment | A::CreateRun | A::ControlRun => self >= Role::Analyst,
            A::Approve => self >= Role::Approver,
            A::ManageMembers | A::ManageSettings | A::ManageTokens => {
                self == Role::Administrator
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    View,
    Comment,
    CreateRun,
    ControlRun,
    Approve,
    ManageMembers,
    ManageSettings,
    ManageTokens,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Comment => "comment",
            Self::CreateRun => "create_run",
            Self::ControlRun => "control_run",
            Self::Approve => "approve",
            Self::ManageMembers => "manage_members",
            Self::ManageSettings => "manage_settings",
            Self::ManageTokens => "manage_tokens",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Automation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub display_name: String,
    pub kind: PrincipalKind,
    pub disabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub enforce_rbac: bool,
    pub separation_of_duties: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub project_id: String,
    pub principal_id: String,
    pub display_name: String,
    pub role: Role,
    pub granted_by: String,
    pub granted_ms: i64,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    pub project_id: String,
    pub role: Role,
    pub invited_by: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub accepted_by: Option<String>,
    pub revoked_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    pub project_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub parent_id: Option<String>,
    pub author: String,
    pub body: String,
    pub revision: i64,
    pub created_ms: i64,
    pub edited_ms: Option<i64>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: i64,
    pub actor: String,
    pub action: String,
    pub project_id: Option<String>,
    pub target: Option<String>,
    pub outcome: String,
    pub detail: Value,
    pub created_ms: i64,
}

const TARGET_KINDS: &[&str] = &["run", "task", "approval", "finding", "report"];

fn valid_principal_id(id: &str) -> bool {
    (3..=120).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.' | '@'))
}

pub struct Collaboration<'a> {
    db: &'a Database,
}

impl<'a> Collaboration<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    fn conn(&self) -> &rusqlite::Connection {
        self.db.connection()
    }

    // ------------------------------------------------------------ audit

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        project_id: Option<&str>,
        target: Option<&str>,
        outcome: &str,
        detail: Value,
    ) {
        let mut detail = detail.to_string();
        if detail.len() > 2048 {
            detail = json!({"truncated": true}).to_string();
        }
        let actor: String = actor.chars().take(160).collect();
        let _ = self.conn().execute(
            "INSERT INTO audit_records(actor,action,project_id,target,outcome,detail_json,created_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                if actor.is_empty() { "unknown".into() } else { actor },
                action.chars().take(64).collect::<String>(),
                project_id,
                target.map(|t| t.chars().take(200).collect::<String>()),
                outcome,
                detail,
                now_ms()
            ],
        );
    }

    pub fn audit_log(
        &self,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT seq,actor,action,project_id,target,outcome,detail_json,created_ms FROM audit_records
                 WHERE (?1 IS NULL OR project_id=?1) ORDER BY seq DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, limit.clamp(1, 1000) as i64], |r| {
                Ok(AuditRecord {
                    seq: r.get(0)?,
                    actor: r.get(1)?,
                    action: r.get(2)?,
                    project_id: r.get(3)?,
                    target: r.get(4)?,
                    outcome: r.get(5)?,
                    detail: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
                    created_ms: r.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    // ------------------------------------------------------- principals

    pub fn ensure_principal(
        &self,
        id: &str,
        display_name: &str,
        kind: PrincipalKind,
    ) -> Result<Principal, String> {
        if !valid_principal_id(id) {
            return Err("principal id must be 3–120 characters of [A-Za-z0-9:_-.@]".into());
        }
        let name: String = display_name.trim().chars().take(120).collect();
        let name = if name.is_empty() { id.to_owned() } else { name };
        self.conn()
            .execute(
                "INSERT INTO principals(id,display_name,kind,created_ms) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(id) DO NOTHING",
                params![
                    id,
                    name,
                    match kind {
                        PrincipalKind::Human => "human",
                        PrincipalKind::Automation => "automation",
                    },
                    now_ms()
                ],
            )
            .map_err(|e| e.to_string())?;
        self.principal(id)?
            .ok_or_else(|| "principal not found".to_owned())
    }

    pub fn principal(&self, id: &str) -> Result<Option<Principal>, String> {
        self.conn()
            .query_row(
                "SELECT id,display_name,kind,disabled FROM principals WHERE id=?1",
                [id],
                |r| {
                    Ok(Principal {
                        id: r.get(0)?,
                        display_name: r.get(1)?,
                        kind: if r.get::<_, String>(2)? == "automation" {
                            PrincipalKind::Automation
                        } else {
                            PrincipalKind::Human
                        },
                        disabled: r.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    // ----------------------------------------------------------- policy

    pub fn policy(&self, project_id: &str) -> Result<AccessPolicy, String> {
        Ok(self
            .conn()
            .query_row(
                "SELECT enforce_rbac, separation_of_duties FROM project_access_policies WHERE project_id=?1",
                [project_id],
                |r| {
                    Ok(AccessPolicy {
                        enforce_rbac: r.get::<_, i64>(0)? != 0,
                        separation_of_duties: r.get::<_, i64>(1)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or_default())
    }

    /// Change the project policy. Turning RBAC on requires the actor to
    /// become (or already be) an administrator, so a project can never be
    /// locked without anyone able to manage it.
    pub fn set_policy(
        &self,
        project_id: &str,
        policy: &AccessPolicy,
        actor: &str,
    ) -> Result<AccessPolicy, String> {
        self.authorize(project_id, actor, Action::ManageSettings)?;
        let tx = self.conn().unchecked_transaction().map_err(|e| e.to_string())?;
        if policy.enforce_rbac {
            let admins: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM project_memberships m JOIN principals p ON p.id=m.principal_id
                     WHERE m.project_id=?1 AND m.role='administrator' AND p.disabled=0 AND p.kind='human'",
                    [project_id],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            if admins == 0 {
                tx.execute(
                    "INSERT INTO project_memberships(project_id,principal_id,role,granted_by,granted_ms)
                     VALUES (?1,?2,'administrator',?2,?3)
                     ON CONFLICT(project_id,principal_id) DO UPDATE SET role='administrator',revision=revision+1",
                    params![project_id, actor, now_ms()],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        tx.execute(
            "INSERT INTO project_access_policies(project_id,enforce_rbac,separation_of_duties,updated_by,updated_ms)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(project_id) DO UPDATE SET enforce_rbac=?2,separation_of_duties=?3,updated_by=?4,updated_ms=?5",
            params![
                project_id,
                i64::from(policy.enforce_rbac),
                i64::from(policy.separation_of_duties),
                actor,
                now_ms()
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        self.audit(
            actor,
            "set_access_policy",
            Some(project_id),
            None,
            "allowed",
            json!(policy),
        );
        self.policy(project_id)
    }

    // ------------------------------------------------------------ roles

    /// Effective role of `principal_id` in `project_id`.
    pub fn role_of(&self, project_id: &str, principal_id: &str) -> Result<Option<Role>, String> {
        let Some(principal) = self.principal(principal_id)? else {
            // Unregistered principals are local operators in single-user
            // mode; automation principals are always registered.
            return Ok((!self.policy(project_id)?.enforce_rbac).then_some(Role::Administrator));
        };
        if principal.disabled {
            return Ok(None);
        }
        let explicit: Option<String> = self
            .conn()
            .query_row(
                "SELECT role FROM project_memberships WHERE project_id=?1 AND principal_id=?2",
                params![project_id, principal_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(role) = explicit {
            return Role::parse(&role).map(Some);
        }
        Ok((!self.policy(project_id)?.enforce_rbac
            && principal.kind == PrincipalKind::Human)
            .then_some(Role::Administrator))
    }

    /// Deterministic authorization. Denials are audited.
    pub fn authorize(&self, project_id: &str, actor: &str, action: Action) -> Result<Role, String> {
        let role = self.role_of(project_id, actor)?;
        let automation = self
            .principal(actor)?
            .is_some_and(|p| p.kind == PrincipalKind::Automation);
        let allowed = match role {
            Some(_) if automation && action == Action::Approve => false,
            Some(role) => role.allows(action),
            None => false,
        };
        if allowed {
            Ok(role.expect("allowed implies a role"))
        } else {
            self.audit(
                actor,
                action.as_str(),
                Some(project_id),
                None,
                "denied",
                json!({"role": role.map(Role::as_str)}),
            );
            Err(format!(
                "access denied: `{actor}` may not {} in this project",
                action.as_str().replace('_', " ")
            ))
        }
    }

    /// Approval authority plus separation of duties: with SoD enabled the
    /// principal that created a run cannot approve it.
    pub fn authorize_approval(
        &self,
        project_id: &str,
        approver: &str,
        run_owner: &str,
    ) -> Result<(), String> {
        self.authorize(project_id, approver, Action::Approve)?;
        if self.policy(project_id)?.separation_of_duties && approver == run_owner {
            self.audit(
                approver,
                "approve",
                Some(project_id),
                None,
                "denied",
                json!({"reason": "separation_of_duties"}),
            );
            return Err(
                "separation of duties: the run owner cannot approve their own run".into(),
            );
        }
        Ok(())
    }

    pub fn members(&self, project_id: &str) -> Result<Vec<Membership>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT m.project_id,m.principal_id,p.display_name,m.role,m.granted_by,m.granted_ms,m.revision
                 FROM project_memberships m JOIN principals p ON p.id=m.principal_id
                 WHERE m.project_id=?1 ORDER BY m.role DESC, p.display_name",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([project_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|r| {
            let (project_id, principal_id, display_name, role, granted_by, granted_ms, revision) =
                r.map_err(|e| e.to_string())?;
            Ok(Membership {
                project_id,
                principal_id,
                display_name,
                role: Role::parse(&role)?,
                granted_by,
                granted_ms,
                revision,
            })
        })
        .collect()
    }

    fn administrators(&self, project_id: &str) -> Result<i64, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM project_memberships WHERE project_id=?1 AND role='administrator'",
                [project_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())
    }

    /// Grant or change a role. `expected_revision` makes concurrent edits
    /// conflict instead of silently overwriting each other.
    pub fn grant(
        &self,
        project_id: &str,
        principal_id: &str,
        role: Role,
        actor: &str,
        expected_revision: Option<i64>,
    ) -> Result<Membership, String> {
        self.authorize(project_id, actor, Action::ManageMembers)?;
        let principal = self
            .principal(principal_id)?
            .ok_or("unknown principal; register it first")?;
        if principal.kind == PrincipalKind::Automation && role >= Role::Approver {
            return Err("automation principals cannot hold approver or administrator roles".into());
        }
        let current: Option<(String, i64)> = self
            .conn()
            .query_row(
                "SELECT role, revision FROM project_memberships WHERE project_id=?1 AND principal_id=?2",
                params![project_id, principal_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let (Some(expected), Some((_, rev))) = (expected_revision, &current) {
            if expected != *rev {
                return Err(format!(
                    "membership changed concurrently (revision {rev}, expected {expected})"
                ));
            }
        }
        if current.as_ref().is_some_and(|(r, _)| r == "administrator")
            && role != Role::Administrator
            && self.administrators(project_id)? <= 1
            && self.policy(project_id)?.enforce_rbac
        {
            return Err("cannot demote the last administrator".into());
        }
        let changed = self
            .conn()
            .execute(
                "INSERT INTO project_memberships(project_id,principal_id,role,granted_by,granted_ms)
                 VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(project_id,principal_id) DO UPDATE SET role=?3,granted_by=?4,granted_ms=?5,
                    revision=revision+1 WHERE revision=?6 OR ?6 IS NULL",
                params![
                    project_id,
                    principal_id,
                    role.as_str(),
                    actor,
                    now_ms(),
                    expected_revision
                ],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("membership changed concurrently".into());
        }
        self.audit(
            actor,
            "grant_role",
            Some(project_id),
            Some(principal_id),
            "allowed",
            json!({"role": role.as_str()}),
        );
        self.members(project_id)?
            .into_iter()
            .find(|m| m.principal_id == principal_id)
            .ok_or_else(|| "membership not found".into())
    }

    pub fn revoke(&self, project_id: &str, principal_id: &str, actor: &str) -> Result<(), String> {
        self.authorize(project_id, actor, Action::ManageMembers)?;
        let role: Option<String> = self
            .conn()
            .query_row(
                "SELECT role FROM project_memberships WHERE project_id=?1 AND principal_id=?2",
                params![project_id, principal_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if role.as_deref() == Some("administrator")
            && self.administrators(project_id)? <= 1
            && self.policy(project_id)?.enforce_rbac
        {
            return Err("cannot remove the last administrator".into());
        }
        self.conn()
            .execute(
                "DELETE FROM project_memberships WHERE project_id=?1 AND principal_id=?2",
                params![project_id, principal_id],
            )
            .map_err(|e| e.to_string())?;
        self.audit(
            actor,
            "revoke_role",
            Some(project_id),
            Some(principal_id),
            "allowed",
            json!({}),
        );
        Ok(())
    }

    // ------------------------------------------------------ invitations

    /// Create a scoped, expiring invitation. The returned code is shown once;
    /// only its SHA-256 verifier is stored.
    pub fn invite(
        &self,
        project_id: &str,
        role: Role,
        actor: &str,
        ttl_ms: i64,
    ) -> Result<(Invitation, String), String> {
        self.authorize(project_id, actor, Action::ManageMembers)?;
        let ttl_ms = ttl_ms.clamp(60_000, 14 * 24 * 3_600_000);
        let code = format!("ctinv_{}", random_secret()?);
        let id = new_id("inv");
        let now = now_ms();
        self.conn()
            .execute(
                "INSERT INTO project_invitations(id,project_id,role,code_sha256,invited_by,created_ms,expires_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    project_id,
                    role.as_str(),
                    sha256_hex(code.as_bytes()),
                    actor,
                    now,
                    now + ttl_ms
                ],
            )
            .map_err(|e| e.to_string())?;
        self.audit(
            actor,
            "invite",
            Some(project_id),
            Some(&id),
            "allowed",
            json!({"role": role.as_str(), "ttl_ms": ttl_ms}),
        );
        Ok((
            Invitation {
                id,
                project_id: project_id.into(),
                role,
                invited_by: actor.into(),
                created_ms: now,
                expires_ms: now + ttl_ms,
                accepted_by: None,
                revoked_ms: None,
            },
            code,
        ))
    }

    /// Accept an invitation once, before expiry, as a human principal.
    pub fn accept_invitation(&self, code: &str, principal_id: &str) -> Result<Membership, String> {
        let principal = self
            .principal(principal_id)?
            .ok_or("register the principal before accepting")?;
        if principal.kind != PrincipalKind::Human || principal.disabled {
            return Err("only active human principals can accept invitations".into());
        }
        let tx = self.conn().unchecked_transaction().map_err(|e| e.to_string())?;
        let row: Option<(String, String, String, i64)> = tx
            .query_row(
                "SELECT id,project_id,role,expires_ms FROM project_invitations
                 WHERE code_sha256=?1 AND accepted_ms IS NULL AND revoked_ms IS NULL",
                [sha256_hex(code.trim().as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((id, project_id, role, expires)) = row else {
            return Err("invitation is invalid, used or revoked".into());
        };
        if expires <= now_ms() {
            return Err("invitation expired".into());
        }
        tx.execute(
            "UPDATE project_invitations SET accepted_by=?2, accepted_ms=?3 WHERE id=?1",
            params![id, principal_id, now_ms()],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO project_memberships(project_id,principal_id,role,granted_by,granted_ms)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(project_id,principal_id) DO UPDATE SET role=?3,granted_by=?4,granted_ms=?5,revision=revision+1",
            params![project_id, principal_id, role, format!("invitation:{id}"), now_ms()],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        self.audit(
            principal_id,
            "accept_invitation",
            Some(&project_id),
            Some(&id),
            "allowed",
            json!({"role": role}),
        );
        self.members(&project_id)?
            .into_iter()
            .find(|m| m.principal_id == principal_id)
            .ok_or_else(|| "membership not found".into())
    }

    pub fn revoke_invitation(&self, invitation_id: &str, actor: &str) -> Result<(), String> {
        let project: String = self
            .conn()
            .query_row(
                "SELECT project_id FROM project_invitations WHERE id=?1",
                [invitation_id],
                |r| r.get(0),
            )
            .map_err(|_| "unknown invitation".to_owned())?;
        self.authorize(&project, actor, Action::ManageMembers)?;
        self.conn()
            .execute(
                "UPDATE project_invitations SET revoked_ms=?2 WHERE id=?1 AND revoked_ms IS NULL",
                params![invitation_id, now_ms()],
            )
            .map_err(|e| e.to_string())?;
        self.audit(
            actor,
            "revoke_invitation",
            Some(&project),
            Some(invitation_id),
            "allowed",
            json!({}),
        );
        Ok(())
    }

    pub fn invitations(&self, project_id: &str) -> Result<Vec<Invitation>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id,project_id,role,invited_by,created_ms,expires_ms,accepted_by,revoked_ms
                 FROM project_invitations WHERE project_id=?1 ORDER BY created_ms DESC LIMIT 100",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([project_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|r| {
            let (id, project_id, role, invited_by, created_ms, expires_ms, accepted_by, revoked_ms) =
                r.map_err(|e| e.to_string())?;
            Ok(Invitation {
                id,
                project_id,
                role: Role::parse(&role)?,
                invited_by,
                created_ms,
                expires_ms,
                accepted_by,
                revoked_ms,
            })
        })
        .collect()
    }

    // --------------------------------------------------------- comments

    fn comment_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Comment> {
        let deleted = r.get::<_, Option<i64>>(10)?.is_some();
        Ok(Comment {
            id: r.get(0)?,
            project_id: r.get(1)?,
            target_kind: r.get(2)?,
            target_id: r.get(3)?,
            parent_id: r.get(4)?,
            author: r.get(5)?,
            body: if deleted {
                String::new()
            } else {
                r.get(6)?
            },
            revision: r.get(7)?,
            created_ms: r.get(8)?,
            edited_ms: r.get(9)?,
            deleted,
        })
    }

    pub fn comment(&self, id: &str) -> Result<Comment, String> {
        self.conn()
            .query_row(
                "SELECT id,project_id,target_kind,target_id,parent_id,author,body,revision,created_ms,edited_ms,deleted_ms
                 FROM collaboration_comments WHERE id=?1",
                [id],
                Self::comment_row,
            )
            .map_err(|_| "unknown comment".to_owned())
    }

    pub fn add_comment(
        &self,
        project_id: &str,
        target_kind: &str,
        target_id: &str,
        parent_id: Option<&str>,
        author: &str,
        body: &str,
    ) -> Result<Comment, String> {
        self.authorize(project_id, author, Action::Comment)?;
        if !TARGET_KINDS.contains(&target_kind) {
            return Err("unsupported comment target".into());
        }
        let body = body.trim();
        if body.is_empty() || body.chars().count() > 4000 {
            return Err("comment must be 1–4000 characters".into());
        }
        if let Some(parent) = parent_id {
            let p = self.comment(parent)?;
            if p.project_id != project_id || p.target_kind != target_kind || p.target_id != target_id
            {
                return Err("reply must stay in the same thread".into());
            }
        }
        let id = new_id("cmt");
        self.conn()
            .execute(
                "INSERT INTO collaboration_comments(id,project_id,target_kind,target_id,parent_id,author,body,created_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![id, project_id, target_kind, target_id, parent_id, author, body, now_ms()],
            )
            .map_err(|e| e.to_string())?;
        self.audit(
            author,
            "comment",
            Some(project_id),
            Some(&format!("{target_kind}:{target_id}")),
            "allowed",
            json!({"comment_id": id}),
        );
        self.comment(&id)
    }

    /// Edit your own comment; the previous body is kept as a revision.
    pub fn edit_comment(
        &self,
        id: &str,
        author: &str,
        body: &str,
        expected_revision: i64,
    ) -> Result<Comment, String> {
        let current = self.comment(id)?;
        if current.author != author {
            return Err("only the author can edit a comment".into());
        }
        if current.deleted {
            return Err("comment was deleted".into());
        }
        let body = body.trim();
        if body.is_empty() || body.chars().count() > 4000 {
            return Err("comment must be 1–4000 characters".into());
        }
        let tx = self.conn().unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO collaboration_comment_revisions(comment_id,revision,body,edited_by,edited_ms)
             SELECT id, revision, body, ?2, ?3 FROM collaboration_comments WHERE id=?1",
            params![id, author, now_ms()],
        )
        .map_err(|e| e.to_string())?;
        let changed = tx
            .execute(
                "UPDATE collaboration_comments SET body=?2, revision=revision+1, edited_ms=?3
                 WHERE id=?1 AND revision=?4",
                params![id, body, now_ms(), expected_revision],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("comment changed concurrently; reload and retry".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        self.comment(id)
    }

    pub fn delete_comment(&self, id: &str, actor: &str) -> Result<(), String> {
        let current = self.comment(id)?;
        if current.author != actor {
            self.authorize(&current.project_id, actor, Action::ManageMembers)?;
        }
        self.conn()
            .execute(
                "UPDATE collaboration_comments SET deleted_ms=?2 WHERE id=?1 AND deleted_ms IS NULL",
                params![id, now_ms()],
            )
            .map_err(|e| e.to_string())?;
        self.audit(
            actor,
            "delete_comment",
            Some(&current.project_id),
            Some(id),
            "allowed",
            json!({}),
        );
        Ok(())
    }

    pub fn comments(
        &self,
        project_id: &str,
        target_kind: &str,
        target_id: &str,
    ) -> Result<Vec<Comment>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id,project_id,target_kind,target_id,parent_id,author,body,revision,created_ms,edited_ms,deleted_ms
                 FROM collaboration_comments WHERE project_id=?1 AND target_kind=?2 AND target_id=?3
                 ORDER BY created_ms LIMIT 500",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, target_kind, target_id], Self::comment_row)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Database, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("c.sqlite3")).unwrap();
        db.connection()
            .execute(
                "INSERT INTO projects(id,root_path,display_name) VALUES ('p1','/tmp/p1','p1')",
                [],
            )
            .unwrap();
        (dir, db, "p1".into())
    }

    #[test]
    fn single_user_mode_keeps_the_local_operator_in_charge() {
        let (_d, db, p) = setup();
        let c = Collaboration::new(&db);
        assert_eq!(c.role_of(&p, "operator:me").unwrap(), Some(Role::Administrator));
        c.authorize(&p, "operator:me", Action::Approve).unwrap();
        c.ensure_principal("api:bot", "bot", PrincipalKind::Automation)
            .unwrap();
        assert!(
            c.authorize(&p, "api:bot", Action::View).is_err(),
            "automation gets no implicit role"
        );
    }

    #[test]
    fn rbac_roles_separation_of_duties_and_last_admin() {
        let (_d, db, p) = setup();
        let c = Collaboration::new(&db);
        c.ensure_principal("operator:alice", "Alice", PrincipalKind::Human)
            .unwrap();
        c.ensure_principal("operator:bob", "Bob", PrincipalKind::Human)
            .unwrap();
        c.set_policy(
            &p,
            &AccessPolicy {
                enforce_rbac: true,
                separation_of_duties: true,
            },
            "operator:alice",
        )
        .unwrap();
        assert_eq!(c.role_of(&p, "operator:alice").unwrap(), Some(Role::Administrator));
        assert_eq!(c.role_of(&p, "operator:bob").unwrap(), None, "no implicit role once enforced");
        assert!(c.authorize(&p, "operator:bob", Action::View).is_err());
        let m = c
            .grant(&p, "operator:bob", Role::Analyst, "operator:alice", None)
            .unwrap();
        c.authorize(&p, "operator:bob", Action::CreateRun).unwrap();
        assert!(c.authorize(&p, "operator:bob", Action::Approve).is_err());
        assert!(
            c.grant(&p, "operator:bob", Role::Approver, "operator:alice", Some(m.revision + 5))
                .is_err(),
            "stale revision conflicts"
        );
        c.grant(&p, "operator:bob", Role::Approver, "operator:alice", Some(m.revision))
            .unwrap();
        c.authorize_approval(&p, "operator:bob", "operator:alice")
            .unwrap();
        assert!(c
            .authorize_approval(&p, "operator:bob", "operator:bob")
            .is_err());
        assert!(
            c.revoke(&p, "operator:alice", "operator:alice").is_err(),
            "last admin stays"
        );
        assert!(c.grant(&p, "operator:alice", Role::Viewer, "operator:bob", None).is_err());
        let denials = c.audit_log(Some(&p), 100).unwrap();
        assert!(denials.iter().any(|a| a.outcome == "denied"));
    }

    #[test]
    fn invitations_are_single_use_and_comments_keep_history() {
        let (_d, db, p) = setup();
        let c = Collaboration::new(&db);
        c.ensure_principal("operator:alice", "Alice", PrincipalKind::Human)
            .unwrap();
        c.ensure_principal("operator:carol", "Carol", PrincipalKind::Human)
            .unwrap();
        c.set_policy(
            &p,
            &AccessPolicy {
                enforce_rbac: true,
                separation_of_duties: false,
            },
            "operator:alice",
        )
        .unwrap();
        let (_inv, code) = c.invite(&p, Role::Viewer, "operator:alice", 3_600_000).unwrap();
        let stored: String = db
            .connection()
            .query_row("SELECT code_sha256 FROM project_invitations", [], |r| r.get(0))
            .unwrap();
        assert_ne!(stored, code, "code is not stored");
        let m = c.accept_invitation(&code, "operator:carol").unwrap();
        assert_eq!(m.role, Role::Viewer);
        assert!(c.accept_invitation(&code, "operator:carol").is_err());
        assert!(
            c.add_comment(&p, "run", "r1", None, "operator:carol", "hi").is_err(),
            "viewers cannot comment"
        );
        let first = c
            .add_comment(&p, "run", "r1", None, "operator:alice", "Looks risky")
            .unwrap();
        let reply = c
            .add_comment(&p, "run", "r1", Some(&first.id), "operator:alice", "Confirmed")
            .unwrap();
        assert!(c
            .add_comment(&p, "run", "r2", Some(&first.id), "operator:alice", "x")
            .is_err());
        let edited = c
            .edit_comment(&first.id, "operator:alice", "Looks risky (edited)", 1)
            .unwrap();
        assert_eq!(edited.revision, 2);
        assert!(c
            .edit_comment(&first.id, "operator:alice", "again", 1)
            .is_err());
        c.delete_comment(&reply.id, "operator:alice").unwrap();
        let thread = c.comments(&p, "run", "r1").unwrap();
        assert_eq!(thread.len(), 2);
        assert!(thread[1].deleted && thread[1].body.is_empty());
    }
}
