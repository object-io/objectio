//! Identity: users, access keys, groups, policies, roles, data filters, the STS signing key.

use super::*;

fn user_meta(u: &StoredUser) -> UserMeta {
    UserMeta {
        user_id: u.user_id.clone(),
        display_name: u.display_name.clone(),
        arn: u.arn.clone(),
        status: u.status,
        created_at: u.created_at,
        email: u.email.clone(),
        tenant: u.tenant.clone(),
        path: shown_path(&u.path).to_string(),
    }
}

fn group_meta(g: &StoredGroup) -> GroupMeta {
    GroupMeta {
        group_id: g.group_id.clone(),
        group_name: g.group_name.clone(),
        arn: g.arn.clone(),
        tenant: group_tenant(&g.arn),
        member_user_ids: g.member_user_ids.clone(),
        created_at: g.created_at,
        path: shown_path(&g.path).to_string(),
    }
}

impl MetaService {
    /// Refuse what format level `level` adds until the cluster is there
    /// (objectio-docs core/upgrade-path.md).
    #[allow(clippy::result_large_err)] // the Status the RPC returns, as is
    fn require_level(&self, level: u32, what: &str) -> Result<(), Status> {
        if self.active_level() >= level {
            Ok(())
        } else {
            Err(Status::failed_precondition(format!(
                "{what} needs format level {level}; the cluster is at {}: finalize the upgrade first",
                self.active_level()
            )))
        }
    }

    /// A live user other than `except` whose name is `name`, ignoring case
    /// (IAM names are case-insensitive).
    fn user_name_taken(&self, name: &str, except: &str) -> bool {
        self.users.read().values().any(|u| {
            u.status != UserStatus::UserDeleted as i32
                && u.user_id != except
                && u.display_name.eq_ignore_ascii_case(name)
        })
    }

    /// A group of `tenant` other than `except` named `name`, ignoring case.
    fn group_name_taken(&self, tenant: &str, name: &str, except: &str) -> bool {
        self.groups.read().values().any(|g| {
            g.group_id != except
                && group_tenant(&g.arn) == tenant
                && g.group_name.eq_ignore_ascii_case(name)
        })
    }

    /// Every inline policy of `principal`, with its stored bytes.
    fn inline_policies_of(&self, principal: &str) -> Vec<(String, Vec<u8>, InlinePolicy)> {
        let prefix = format!("{principal}\u{0}");
        self.store
            .as_ref()
            .map(|s| s.list_named(INLINE_POLICIES_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(k, b)| {
                let p = InlinePolicy::decode(b.as_slice()).ok()?;
                Some((k, b, p))
            })
            .collect()
    }

    /// The writes that drop everything hanging off `principal` ("user:…",
    /// "group:…", "role:…"): its inline policies and its attachments. A
    /// recreated principal of the same name must start with nothing.
    fn principal_cleanup_ops(&self, principal: &str) -> Vec<objectio_meta_store::CasOp> {
        use objectio_meta_store::{CasOp, CasTable};
        let mut ops: Vec<CasOp> = self
            .inline_policies_of(principal)
            .into_iter()
            .map(|(key, bytes, _)| CasOp {
                table: CasTable::Named(INLINE_POLICIES_TABLE.into()),
                key,
                expected: Some(bytes),
                new_value: None,
            })
            .collect();
        if let Some(names) = self.policy_attachments.read().get(principal) {
            ops.push(CasOp {
                table: CasTable::PolicyAttachments,
                key: principal.to_string(),
                expected: Some(names.join(",").into_bytes()),
                new_value: None,
            });
        }
        ops
    }

    /// Mirror [`Self::principal_cleanup_ops`] once committed.
    fn forget_principal(&self, principal: &str) {
        self.policy_attachments.write().remove(principal);
    }

    pub(super) fn apply_user_event(&self, key: &str, new_value: Option<&[u8]>) {
        let mut m = self.users.write();
        match new_value {
            Some(bytes) => match objectio_meta_store::record::deserialize::<StoredUser>(bytes) {
                Ok(u) => {
                    m.insert(key.to_string(), u);
                }
                Err(e) => warn!("apply: decode StoredUser('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_access_key_event(&self, key: &str, new_value: Option<&[u8]>) {
        let mut m = self.access_keys.write();
        match new_value {
            Some(bytes) => {
                match objectio_meta_store::record::deserialize::<objectio_meta_store::StoredAccessKey>(
                    bytes,
                ) {
                    Ok(k) => {
                        // Keep user_keys index consistent: insert the
                        // access_key_id under the owning user if absent.
                        let user_id = k.user_id.clone();
                        m.insert(key.to_string(), k);
                        drop(m);
                        let mut idx = self.user_keys.write();
                        let ids = idx.entry(user_id).or_default();
                        if !ids.iter().any(|k2| k2 == key) {
                            ids.push(key.to_string());
                        }
                    }
                    Err(e) => warn!("apply: decode StoredAccessKey('{key}') failed: {e}"),
                }
            }
            None => {
                let removed = m.remove(key);
                drop(m);
                if let Some(k) = removed {
                    let mut idx = self.user_keys.write();
                    if let Some(ids) = idx.get_mut(&k.user_id) {
                        ids.retain(|k2| k2 != key);
                    }
                }
            }
        }
    }

    /// Create admin user if no users exist
    /// The admin's first key, once the admin exists with one.
    pub fn admin_credentials(&self, admin_name: &str) -> Option<(String, String)> {
        let admin = self
            .users
            .read()
            .values()
            .find(|u| u.display_name == admin_name && u.tenant.is_empty())
            .cloned()?;
        let keys = self.user_keys.read();
        let first = keys.get(&admin.user_id)?.first()?;
        self.access_keys
            .read()
            .get(first)
            .map(|k| (k.access_key_id.clone(), k.secret_access_key.clone()))
    }

    /// Create the bootstrap admin and its key through the ordinary,
    /// replicated user and key calls — on the leader, when there are no
    /// users yet (or the admin lost the race to get its key: a leader that
    /// died between the two).
    pub async fn create_admin(&self, admin_name: &str) -> Result<(), Status> {
        let existing = self
            .users
            .read()
            .values()
            .find(|u| u.display_name == admin_name && u.tenant.is_empty())
            .map(|u| u.user_id.clone());
        let user_id = match existing {
            Some(id) => id,
            None if self.users.read().is_empty() => self
                .create_user(Request::new(CreateUserRequest {
                    display_name: admin_name.to_string(),
                    ..Default::default()
                }))
                .await?
                .into_inner()
                .user
                .map(|u| u.user_id)
                .ok_or_else(|| Status::internal("created the admin, but got no user back"))?,
            // Users exist and none is the admin: an operator's choice.
            None => return Ok(()),
        };
        if self
            .user_keys
            .read()
            .get(&user_id)
            .is_none_or(Vec::is_empty)
        {
            self.create_access_key(Request::new(CreateAccessKeyRequest {
                user_id,
                ..Default::default()
            }))
            .await?;
        }
        Ok(())
    }

    pub fn ensure_admin(&self, admin_name: &str) -> Option<(String, String)> {
        let users = self.users.read();
        if !users.is_empty() {
            // Users exist, check if admin already has keys
            drop(users);
            let user = self
                .users
                .read()
                .values()
                .find(|u| u.display_name == admin_name)
                .cloned();
            if let Some(admin_user) = user {
                let keys = self.user_keys.read();
                if let Some(key_ids) = keys.get(&admin_user.user_id)
                    && let Some(first_key_id) = key_ids.first()
                    && let Some(key) = self.access_keys.read().get(first_key_id)
                {
                    return Some((key.access_key_id.clone(), key.secret_access_key.clone()));
                }
            }
            return None;
        }
        drop(users);

        // Create admin user
        let user_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();
        let user = StoredUser {
            user_id: user_id.clone(),
            display_name: admin_name.to_string(),
            arn: format!("arn:objectio:iam::user/{}", admin_name),
            status: UserStatus::UserActive as i32,
            created_at: now,
            email: String::new(),
            tenant: String::new(), // system admin has no tenant
            path: String::new(),
        };

        self.users.write().insert(user_id.clone(), user.clone());
        self.user_keys.write().insert(user_id.clone(), Vec::new());

        // Create access key
        let access_key_id = Self::generate_access_key_id();
        let secret_access_key = Self::generate_secret_access_key();

        let key = StoredAccessKey {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            user_id: user_id.clone(),
            status: KeyStatus::KeyActive as i32,
            created_at: now,
            tenant: String::new(),
            // The bootstrap admin key is deliberately unscoped.
            scope: String::new(),
            operation: 0,
        };

        self.access_keys
            .write()
            .insert(access_key_id.clone(), key.clone());
        self.user_keys
            .write()
            .entry(user_id)
            .or_default()
            .push(access_key_id.clone());

        // Persist admin user + key atomically
        if let Some(store) = &self.store {
            store.put_user_and_key(&user, &key);
        }

        info!(
            "Created admin user '{}' with access key {}",
            admin_name, access_key_id
        );

        Some((access_key_id, secret_access_key))
    }

    /// Generate AWS-style access key ID (20 chars, starts with AKIA)
    pub(super) fn generate_access_key_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
        let suffix: String = (0..16)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect();
        format!("AKIA{}", suffix)
    }

    /// Generate AWS-style secret access key (40 chars, base64-like)
    pub(super) fn generate_secret_access_key() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
        (0..40)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect()
    }

    pub(super) fn role(&self, name: &str) -> Option<RoleObject> {
        let bytes = self.store.as_ref()?.read_named(ROLES_TABLE, name)?;
        RoleObject::decode(bytes.as_slice()).ok()
    }

    pub(crate) async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();

        if req.display_name.is_empty() {
            return Err(Status::invalid_argument("display_name is required"));
        }
        let path = iam_path(&req.path)?;
        if path != "/" {
            self.require_level(LEVEL_IAM_API, "a user path")?;
        }

        // Check if a *live* user with this name exists. DeleteUser is a soft
        // delete — it flips status to Deleted and leaves the record in place —
        // so scanning every value meant a deleted name was taken forever.
        // Listing already hides those users, which made it look like the name
        // was free right up until the create failed. Names are
        // case-insensitive, as in IAM.
        if self.user_name_taken(&req.display_name, "") {
            return Err(Status::already_exists("user with this name already exists"));
        }

        let user_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();

        // Validate tenant if specified
        let tenant = req.tenant.clone();
        if !tenant.is_empty() && !self.tenants.read().contains_key(&tenant) {
            return Err(Status::not_found(format!("tenant '{}' not found", tenant)));
        }

        // Include tenant in ARN if tenant-scoped
        let arn = user_arn(&tenant, &path, &req.display_name);

        let user = StoredUser {
            user_id: user_id.clone(),
            display_name: req.display_name.clone(),
            arn,
            status: UserStatus::UserActive as i32,
            created_at: now,
            email: req.email.clone(),
            tenant: tenant.clone(),
            path: stored_path(&path),
        };

        // Replicate through Raft. expected=None ensures the user_id
        // hasn't collided with a concurrent create (cryptographically
        // unlikely for UUIDs, but tested correctly by the state machine).
        let user_bytes = objectio_meta_store::record::serialize(&user)
            .map_err(|e| Status::internal(format!("user encode: {e}")))?;
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Users,
                    key: user_id.clone(),
                    expected: None,
                    new_value: Some(user_bytes),
                }],
                requested_by: "create-user".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists(
                            "user_id collision (retry with fresh id)",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for create_user: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_user(&user_id, &user);
        }

        self.users.write().insert(user_id.clone(), user.clone());
        self.user_keys.write().insert(user_id.clone(), Vec::new());

        info!(
            "Created user: {} (tenant={})",
            req.display_name,
            if tenant.is_empty() { "system" } else { &tenant }
        );

        Ok(Response::new(CreateUserResponse {
            user: Some(user_meta(&user)),
        }))
    }

    pub(crate) async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let req = request.into_inner();

        let user = self
            .users
            .read()
            .get(&req.user_id)
            .cloned()
            .ok_or_else(|| Status::not_found("user not found"))?;

        Ok(Response::new(GetUserResponse {
            user: Some(user_meta(&user)),
        }))
    }

    pub(crate) async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let req = request.into_inner();
        let max_results = if req.max_results == 0 {
            100
        } else {
            req.max_results.min(1000)
        };

        // In id order: the marker is the last id of the page before, and
        // the map has no order of its own.
        let mut users: Vec<UserMeta> = self
            .users
            .read()
            .values()
            .filter(|u| req.marker.is_empty() || u.user_id > req.marker)
            .filter(|u| u.status != UserStatus::UserDeleted as i32)
            .map(user_meta)
            .collect();
        users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        users.truncate(max_results as usize + 1);

        let is_truncated = users.len() > max_results as usize;
        let users: Vec<UserMeta> = users.into_iter().take(max_results as usize).collect();
        let next_marker = users.last().map(|u| u.user_id.clone()).unwrap_or_default();

        Ok(Response::new(ListUsersResponse {
            users,
            next_marker: if is_truncated {
                next_marker
            } else {
                String::new()
            },
            is_truncated,
        }))
    }

    pub(crate) async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = request.into_inner();

        // Snapshot current user + access-key state under read locks so we
        // can build the CAS batch atomically. The user's status flips to
        // Deleted; every owned access key flips to Inactive — all in one
        // MultiCas so followers see the compound change at the same log
        // position (can't observe "user deleted but keys still active").
        let (old_user_bytes, new_user_bytes, user_snapshot) = {
            let users = self.users.read();
            let user = users
                .get(&req.user_id)
                .ok_or_else(|| Status::not_found("user not found"))?;
            let mut new_user = user.clone();
            new_user.status = UserStatus::UserDeleted as i32;
            let old_bytes = objectio_meta_store::record::serialize(user)
                .map_err(|e| Status::internal(format!("user encode: {e}")))?;
            let new_bytes = objectio_meta_store::record::serialize(&new_user)
                .map_err(|e| Status::internal(format!("user encode: {e}")))?;
            (old_bytes, new_bytes, new_user)
        };

        let key_ids: Vec<String> = self
            .user_keys
            .read()
            .get(&req.user_id)
            .cloned()
            .unwrap_or_default();

        // Build per-key (old_bytes, new_bytes) transitions. Keys that
        // aren't found in the access_keys map are silently skipped (stale
        // entry in user_keys index).
        let mut key_transitions: Vec<(String, Vec<u8>, Vec<u8>, StoredAccessKey)> =
            Vec::with_capacity(key_ids.len());
        {
            let keys = self.access_keys.read();
            for key_id in &key_ids {
                if let Some(key) = keys.get(key_id) {
                    let mut new_key = key.clone();
                    new_key.status = KeyStatus::KeyInactive as i32;
                    let old_b = objectio_meta_store::record::serialize(key)
                        .map_err(|e| Status::internal(format!("key encode: {e}")))?;
                    let new_b = objectio_meta_store::record::serialize(&new_key)
                        .map_err(|e| Status::internal(format!("key encode: {e}")))?;
                    key_transitions.push((key_id.clone(), old_b, new_b, new_key));
                }
            }
        }

        // Nothing stays hanging off a deleted user: its inline policies,
        // its attachments, its group memberships.
        let principal = format!("user:{}", req.user_id);
        let mut group_transitions: Vec<(String, Vec<u8>, Vec<u8>, StoredGroup)> = Vec::new();
        for g in self.groups.read().values() {
            if g.member_user_ids.contains(&req.user_id) {
                let mut after = g.clone();
                after.member_user_ids.retain(|m| m != &req.user_id);
                let old_b = objectio_meta_store::record::serialize(g)
                    .map_err(|e| Status::internal(format!("group encode: {e}")))?;
                let new_b = objectio_meta_store::record::serialize(&after)
                    .map_err(|e| Status::internal(format!("group encode: {e}")))?;
                group_transitions.push((g.group_id.clone(), old_b, new_b, after));
            }
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(1 + key_transitions.len());
            ops.push(CasOp {
                table: CasTable::Users,
                key: req.user_id.clone(),
                expected: Some(old_user_bytes),
                new_value: Some(new_user_bytes),
            });
            for (kid, old_b, new_b, _) in &key_transitions {
                ops.push(CasOp {
                    table: CasTable::AccessKeys,
                    key: kid.clone(),
                    expected: Some(old_b.clone()),
                    new_value: Some(new_b.clone()),
                });
            }
            for (gid, old_b, new_b, _) in &group_transitions {
                ops.push(CasOp {
                    table: CasTable::Groups,
                    key: gid.clone(),
                    expected: Some(old_b.clone()),
                    new_value: Some(new_b.clone()),
                });
            }
            ops.extend(self.principal_cleanup_ops(&principal));
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-user".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "user or access-key changed mid-delete; retry (conflicts at ops {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for delete_user: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_user(&req.user_id, &user_snapshot);
            for (kid, _, _, new_key) in &key_transitions {
                store.put_access_key(kid, new_key);
            }
            for (gid, _, _, group) in &group_transitions {
                store.put_group(gid, group);
            }
            for op in self.principal_cleanup_ops(&principal) {
                store.write_named(
                    objectio_meta_store::cas_table_name(&op.table),
                    &op.key,
                    None,
                );
            }
        }

        // Mirror into in-memory caches after the quorum commit.
        self.users
            .write()
            .insert(req.user_id.clone(), user_snapshot);
        {
            let mut keys = self.access_keys.write();
            for (kid, _, _, new_key) in key_transitions {
                keys.insert(kid, new_key);
            }
        }
        {
            let mut groups = self.groups.write();
            for (gid, _, _, group) in group_transitions {
                groups.insert(gid, group);
            }
        }
        self.forget_principal(&principal);

        info!("Deleted user: {}", req.user_id);

        Ok(Response::new(DeleteUserResponse { success: true }))
    }

    pub(crate) async fn create_access_key(
        &self,
        request: Request<CreateAccessKeyRequest>,
    ) -> Result<Response<CreateAccessKeyResponse>, Status> {
        let req = request.into_inner();

        // Verify user exists and is active
        let user = self
            .users
            .read()
            .get(&req.user_id)
            .cloned()
            .ok_or_else(|| Status::not_found("user not found"))?;

        if user.status != UserStatus::UserActive as i32 {
            return Err(Status::failed_precondition("user is not active"));
        }

        let now = Self::current_timestamp();
        let access_key_id = Self::generate_access_key_id();
        let secret_access_key = Self::generate_secret_access_key();

        let key = StoredAccessKey {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            user_id: req.user_id.clone(),
            status: KeyStatus::KeyActive as i32,
            created_at: now,
            tenant: user.tenant.clone(),
            scope: req.scope.clone(),
            operation: req.operation,
        };

        let key_bytes = objectio_meta_store::record::serialize(&key)
            .map_err(|e| Status::internal(format!("access key encode: {e}")))?;
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    // No enum variant yet for access_keys — use Named
                    // escape hatch. Switching to a dedicated CasTable
                    // variant later is additive.
                    table: CasTable::AccessKeys,
                    key: access_key_id.clone(),
                    expected: None,
                    new_value: Some(key_bytes),
                }],
                requested_by: "create-access-key".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists(
                            "access key id collision (retry with fresh id)",
                        ));
                    }
                    other => {
                        error!(
                            "unexpected raft response for create_access_key: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_access_key(&access_key_id, &key);
        }

        self.access_keys
            .write()
            .insert(access_key_id.clone(), key.clone());
        // `apply_access_key_event` maintains this index too, and the raft
        // write above already ran it — without a guard every key lands twice
        // and `key list` shows duplicates.
        {
            let mut idx = self.user_keys.write();
            let ids = idx.entry(req.user_id.clone()).or_default();
            if !ids.contains(&access_key_id) {
                ids.push(access_key_id.clone());
            }
        }

        info!(
            "Created access key {} for user {}",
            access_key_id, req.user_id
        );

        Ok(Response::new(CreateAccessKeyResponse {
            access_key: Some(AccessKeyMeta {
                access_key_id: key.access_key_id,
                secret_access_key: key.secret_access_key, // Only returned on creation
                user_id: key.user_id,
                status: key.status,
                created_at: key.created_at,
                tenant: key.tenant,
                scope: key.scope,
                operation: key.operation,
            }),
        }))
    }

    pub(crate) async fn list_access_keys(
        &self,
        request: Request<ListAccessKeysRequest>,
    ) -> Result<Response<ListAccessKeysResponse>, Status> {
        let req = request.into_inner();

        let key_ids = self
            .user_keys
            .read()
            .get(&req.user_id)
            .cloned()
            .unwrap_or_default();

        let keys = self.access_keys.read();
        let access_keys: Vec<AccessKeyMeta> = key_ids
            .iter()
            .filter_map(|id| keys.get(id))
            .map(|k| AccessKeyMeta {
                access_key_id: k.access_key_id.clone(),
                secret_access_key: String::new(), // Don't return secret in list
                user_id: k.user_id.clone(),
                status: k.status,
                created_at: k.created_at,
                tenant: k.tenant.clone(),
                scope: k.scope.clone(),
                operation: k.operation,
            })
            .collect();

        Ok(Response::new(ListAccessKeysResponse { access_keys }))
    }

    pub(crate) async fn delete_access_key(
        &self,
        request: Request<DeleteAccessKeyRequest>,
    ) -> Result<Response<DeleteAccessKeyResponse>, Status> {
        let req = request.into_inner();

        let current = self
            .access_keys
            .read()
            .get(&req.access_key_id)
            .cloned()
            .ok_or_else(|| Status::not_found("access key not found"))?;
        let expected_bytes = objectio_meta_store::record::serialize(&current)
            .map_err(|e| Status::internal(format!("access key encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::AccessKeys,
                    key: req.access_key_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: None, // delete
                }],
                requested_by: "delete-access-key".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "access key changed since read; retry delete",
                        ));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_access_key: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_access_key(&req.access_key_id);
        }

        self.access_keys.write().remove(&req.access_key_id);
        if let Some(keys) = self.user_keys.write().get_mut(&current.user_id) {
            keys.retain(|id| id != &req.access_key_id);
        }

        info!("Deleted access key: {}", req.access_key_id);
        Ok(Response::new(DeleteAccessKeyResponse { success: true }))
    }

    pub(crate) async fn get_access_key(
        &self,
        request: Request<objectio_proto::metadata::GetAccessKeyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetAccessKeyResponse>, Status> {
        let id = request.into_inner().access_key_id;
        let key = self.access_keys.read().get(&id).cloned();
        Ok(Response::new(
            objectio_proto::metadata::GetAccessKeyResponse {
                found: key.is_some(),
                access_key: key.map(|k| AccessKeyMeta {
                    access_key_id: k.access_key_id,
                    secret_access_key: String::new(),
                    user_id: k.user_id,
                    status: k.status,
                    created_at: k.created_at,
                    tenant: k.tenant,
                    scope: k.scope,
                    operation: k.operation,
                }),
            },
        ))
    }

    pub(crate) async fn get_access_key_for_auth(
        &self,
        request: Request<GetAccessKeyForAuthRequest>,
    ) -> Result<Response<GetAccessKeyForAuthResponse>, Status> {
        let req = request.into_inner();

        let key = self
            .access_keys
            .read()
            .get(&req.access_key_id)
            .cloned()
            .ok_or_else(|| Status::not_found("access key not found"))?;

        if key.status != KeyStatus::KeyActive as i32 {
            return Err(Status::permission_denied("access key is inactive"));
        }

        let user = self
            .users
            .read()
            .get(&key.user_id)
            .cloned()
            .ok_or_else(|| Status::not_found("user not found"))?;

        if user.status != UserStatus::UserActive as i32 {
            return Err(Status::permission_denied("user is not active"));
        }

        Ok(Response::new(GetAccessKeyForAuthResponse {
            access_key: Some(AccessKeyMeta {
                access_key_id: key.access_key_id,
                secret_access_key: key.secret_access_key, // Include for auth verification
                user_id: key.user_id,
                status: key.status,
                created_at: key.created_at,
                tenant: key.tenant,
                scope: key.scope,
                operation: key.operation,
            }),
            user: Some(user_meta(&user)),
        }))
    }

    pub(crate) async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let req = request.into_inner();

        if req.group_name.is_empty() {
            return Err(Status::invalid_argument("group_name is required"));
        }
        let path = iam_path(&req.path)?;
        if path != "/" {
            self.require_level(LEVEL_IAM_API, "a group path")?;
        }

        // Unique within its tenant, ignoring case.
        let arn = group_arn(&req.tenant, &path, &req.group_name);
        if self.group_name_taken(&req.tenant, &req.group_name, "") {
            return Err(Status::already_exists(
                "group with this name already exists",
            ));
        }

        let group_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();

        let group = StoredGroup {
            group_id: group_id.clone(),
            group_name: req.group_name.clone(),
            arn,
            member_user_ids: Vec::new(),
            created_at: now,
            path: stored_path(&path),
        };
        let group_bytes = objectio_meta_store::record::serialize(&group)
            .map_err(|e| Status::internal(format!("group encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: group_id.clone(),
                    expected: None,
                    new_value: Some(group_bytes),
                }],
                requested_by: "create-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists(
                            "group_id collision (retry with fresh id)",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for create_group: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_group(&group_id, &group);
        }

        self.groups.write().insert(group_id.clone(), group.clone());
        info!("Created group: {}", req.group_name);

        Ok(Response::new(CreateGroupResponse {
            group: Some(group_meta(&group)),
        }))
    }

    pub(crate) async fn update_group(
        &self,
        request: Request<UpdateGroupRequest>,
    ) -> Result<Response<UpdateGroupResponse>, Status> {
        let req = request.into_inner();
        self.require_level(LEVEL_IAM_API, "renaming a group")?;
        let old = self
            .groups
            .read()
            .get(&req.group_id)
            .cloned()
            .ok_or_else(|| Status::not_found("group not found"))?;
        let tenant = group_tenant(&old.arn);
        let mut new = old.clone();
        if let Some(name) = req.group_name {
            if name.is_empty() {
                return Err(Status::invalid_argument("group_name is required"));
            }
            if self.group_name_taken(&tenant, &name, &old.group_id) {
                return Err(Status::already_exists(
                    "group with this name already exists",
                ));
            }
            new.group_name = name;
        }
        if let Some(path) = req.path {
            new.path = stored_path(&iam_path(&path)?);
        }
        new.arn = group_arn(&tenant, &new.path, &new.group_name);
        let enc = |g: &StoredGroup| -> Result<Vec<u8>, Box<Status>> {
            objectio_meta_store::record::serialize(g)
                .map_err(|e| Box::new(Status::internal(format!("group encode: {e}"))))
        };
        self.cas_one(
            objectio_meta_store::CasTable::Groups,
            &req.group_id,
            Some(enc(&old).map_err(|e| *e)?),
            Some(enc(&new).map_err(|e| *e)?),
            "update-group",
        )
        .await?;
        self.groups
            .write()
            .insert(req.group_id.clone(), new.clone());
        info!("Updated group {} ({})", req.group_id, new.arn);
        Ok(Response::new(UpdateGroupResponse {
            group: Some(group_meta(&new)),
        }))
    }

    pub(crate) async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        let req = request.into_inner();
        let expected_bytes = {
            let groups = self.groups.read();
            let g = groups
                .get(&req.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            objectio_meta_store::record::serialize(g)
                .map_err(|e| Status::internal(format!("group encode: {e}")))?
        };

        // Its inline policies and attachments go with it.
        let principal = format!("group:{}", req.group_id);
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::Groups,
                key: req.group_id.clone(),
                expected: Some(expected_bytes),
                new_value: None,
            }];
            ops.extend(self.principal_cleanup_ops(&principal));
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("group changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_group: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_group(&req.group_id);
            for op in self.principal_cleanup_ops(&principal) {
                store.write_named(
                    objectio_meta_store::cas_table_name(&op.table),
                    &op.key,
                    None,
                );
            }
        }

        self.groups.write().remove(&req.group_id);
        self.forget_principal(&principal);
        info!("Deleted group: {}", req.group_id);

        Ok(Response::new(DeleteGroupResponse { success: true }))
    }

    pub(crate) async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<ListGroupsResponse>, Status> {
        let req = request.into_inner();
        let max_results = if req.max_results == 0 {
            100
        } else {
            req.max_results.min(1000)
        };

        let mut groups: Vec<GroupMeta> = self
            .groups
            .read()
            .values()
            .filter(|g| req.marker.is_empty() || g.group_id > req.marker)
            .map(group_meta)
            .collect();
        groups.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        groups.truncate(max_results as usize + 1);

        let is_truncated = groups.len() > max_results as usize;
        let groups: Vec<GroupMeta> = groups.into_iter().take(max_results as usize).collect();
        let next_marker = groups
            .last()
            .map(|g| g.group_id.clone())
            .unwrap_or_default();

        Ok(Response::new(ListGroupsResponse {
            groups,
            next_marker: if is_truncated {
                next_marker
            } else {
                String::new()
            },
            is_truncated,
        }))
    }

    pub(crate) async fn add_user_to_group(
        &self,
        request: Request<AddUserToGroupRequest>,
    ) -> Result<Response<AddUserToGroupResponse>, Status> {
        let req = request.into_inner();

        if !self.users.read().contains_key(&req.user_id) {
            return Err(Status::not_found("user not found"));
        }

        let (expected_bytes, new_group) = {
            let groups = self.groups.read();
            let current = groups
                .get(&req.group_id)
                .cloned()
                .ok_or_else(|| Status::not_found("group not found"))?;
            if current.member_user_ids.contains(&req.user_id) {
                return Err(Status::already_exists("user already in group"));
            }
            let expected = objectio_meta_store::record::serialize(&current)
                .map_err(|e| Status::internal(format!("group encode: {e}")))?;
            let mut new_group = current;
            new_group.member_user_ids.push(req.user_id.clone());
            (expected, new_group)
        };
        let new_bytes = objectio_meta_store::record::serialize(&new_group)
            .map_err(|e| Status::internal(format!("group encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: req.group_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "add-user-to-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("group changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for add_user_to_group: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_group(&req.group_id, &new_group);
        }

        self.groups.write().insert(req.group_id.clone(), new_group);
        info!("Added user {} to group {}", req.user_id, req.group_id);
        Ok(Response::new(AddUserToGroupResponse { success: true }))
    }

    pub(crate) async fn remove_user_from_group(
        &self,
        request: Request<RemoveUserFromGroupRequest>,
    ) -> Result<Response<RemoveUserFromGroupResponse>, Status> {
        let req = request.into_inner();

        let (expected_bytes, new_group) = {
            let groups = self.groups.read();
            let current = groups
                .get(&req.group_id)
                .cloned()
                .ok_or_else(|| Status::not_found("group not found"))?;
            if !current.member_user_ids.contains(&req.user_id) {
                return Err(Status::not_found("user not in group"));
            }
            let expected = objectio_meta_store::record::serialize(&current)
                .map_err(|e| Status::internal(format!("group encode: {e}")))?;
            let mut new_group = current;
            new_group.member_user_ids.retain(|id| id != &req.user_id);
            (expected, new_group)
        };
        let new_bytes = objectio_meta_store::record::serialize(&new_group)
            .map_err(|e| Status::internal(format!("group encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: req.group_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "remove-user-from-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("group changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for remove_user_from_group: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_group(&req.group_id, &new_group);
        }

        self.groups.write().insert(req.group_id.clone(), new_group);
        info!("Removed user {} from group {}", req.user_id, req.group_id);
        Ok(Response::new(RemoveUserFromGroupResponse { success: true }))
    }

    pub(crate) async fn get_user_groups(
        &self,
        request: Request<GetUserGroupsRequest>,
    ) -> Result<Response<GetUserGroupsResponse>, Status> {
        let req = request.into_inner();

        // Validate user exists
        if !self.users.read().contains_key(&req.user_id) {
            return Err(Status::not_found("user not found"));
        }

        let groups: Vec<GroupMeta> = self
            .groups
            .read()
            .values()
            .filter(|g| g.member_user_ids.contains(&req.user_id))
            .map(group_meta)
            .collect();

        Ok(Response::new(GetUserGroupsResponse { groups }))
    }

    pub(crate) async fn create_data_filter(
        &self,
        request: Request<CreateDataFilterRequest>,
    ) -> Result<Response<CreateDataFilterResponse>, Status> {
        let req = request.into_inner();
        let filter_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let filter = StoredDataFilter {
            filter_id: filter_id.clone(),
            filter_name: req.filter_name.clone(),
            namespace_levels: req.namespace_levels.clone(),
            table_name: req.table_name.clone(),
            principal_arns: req.principal_arns.clone(),
            allowed_columns: req.allowed_columns.clone(),
            excluded_columns: req.excluded_columns.clone(),
            row_filter_expression: req.row_filter_expression.clone(),
            created_at: now,
            updated_at: now,
        };

        let bytes = objectio_meta_store::record::serialize(&filter)
            .map_err(|e| Status::internal(format!("data_filter encode: {e}")))?;
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DataFilters,
                    key: filter_id.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-data-filter".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("filter_id collision"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for create_data_filter: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_data_filter(&filter_id, &filter);
        }
        self.data_filters
            .write()
            .insert(filter_id.clone(), filter.clone());

        info!(
            filter_id = %filter.filter_id,
            filter_name = %filter.filter_name,
            table = %filter.table_name,
            "data_filter.created"
        );

        Ok(Response::new(CreateDataFilterResponse {
            filter: Some(IcebergDataFilter {
                filter_id: filter.filter_id,
                filter_name: filter.filter_name,
                namespace_levels: filter.namespace_levels,
                table_name: filter.table_name,
                principal_arns: filter.principal_arns,
                allowed_columns: filter.allowed_columns,
                excluded_columns: filter.excluded_columns,
                row_filter_expression: filter.row_filter_expression,
                created_at: filter.created_at,
                updated_at: filter.updated_at,
            }),
        }))
    }

    pub(crate) async fn list_data_filters(
        &self,
        request: Request<ListDataFiltersRequest>,
    ) -> Result<Response<ListDataFiltersResponse>, Status> {
        let req = request.into_inner();
        let ns_key = req.namespace_levels.join("\x00");

        let filters: Vec<IcebergDataFilter> = self
            .data_filters
            .read()
            .values()
            .filter(|f| f.namespace_levels.join("\x00") == ns_key && f.table_name == req.table_name)
            .map(|f| IcebergDataFilter {
                filter_id: f.filter_id.clone(),
                filter_name: f.filter_name.clone(),
                namespace_levels: f.namespace_levels.clone(),
                table_name: f.table_name.clone(),
                principal_arns: f.principal_arns.clone(),
                allowed_columns: f.allowed_columns.clone(),
                excluded_columns: f.excluded_columns.clone(),
                row_filter_expression: f.row_filter_expression.clone(),
                created_at: f.created_at,
                updated_at: f.updated_at,
            })
            .collect();

        Ok(Response::new(ListDataFiltersResponse { filters }))
    }

    pub(crate) async fn delete_data_filter(
        &self,
        request: Request<DeleteDataFilterRequest>,
    ) -> Result<Response<DeleteDataFilterResponse>, Status> {
        let req = request.into_inner();
        let expected = {
            let filters = self.data_filters.read();
            let Some(f) = filters.get(&req.filter_id) else {
                return Ok(Response::new(DeleteDataFilterResponse { success: false }));
            };
            objectio_meta_store::record::serialize(f)
                .map_err(|e| Status::internal(format!("data_filter encode: {e}")))?
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DataFilters,
                    key: req.filter_id.clone(),
                    expected: Some(expected),
                    new_value: None,
                }],
                requested_by: "delete-data-filter".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("filter changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_data_filter: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_data_filter(&req.filter_id);
        }

        self.data_filters.write().remove(&req.filter_id);
        Ok(Response::new(DeleteDataFilterResponse { success: true }))
    }

    pub(crate) async fn get_data_filters_for_principal(
        &self,
        request: Request<GetDataFiltersForPrincipalRequest>,
    ) -> Result<Response<ListDataFiltersResponse>, Status> {
        let req = request.into_inner();
        let ns_key = req.namespace_levels.join("\x00");

        let all_arns: Vec<&str> = std::iter::once(req.principal_arn.as_str())
            .chain(req.group_arns.iter().map(String::as_str))
            .collect();

        let filters: Vec<IcebergDataFilter> = self
            .data_filters
            .read()
            .values()
            .filter(|f| {
                f.namespace_levels.join("\x00") == ns_key
                    && f.table_name == req.table_name
                    && f.principal_arns
                        .iter()
                        .any(|p| p == "*" || all_arns.iter().any(|a| a == p))
            })
            .map(|f| IcebergDataFilter {
                filter_id: f.filter_id.clone(),
                filter_name: f.filter_name.clone(),
                namespace_levels: f.namespace_levels.clone(),
                table_name: f.table_name.clone(),
                principal_arns: f.principal_arns.clone(),
                allowed_columns: f.allowed_columns.clone(),
                excluded_columns: f.excluded_columns.clone(),
                row_filter_expression: f.row_filter_expression.clone(),
                created_at: f.created_at,
                updated_at: f.updated_at,
            })
            .collect();

        Ok(Response::new(ListDataFiltersResponse { filters }))
    }

    pub(crate) async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        let req = request.into_inner();
        let plain = req.name.trim().to_string();
        // An attachment names an AWS managed policy "aws:<name>": a stored
        // one can't look like that.
        if !iam_name_ok(&plain, 128) {
            return Err(Status::invalid_argument(
                "Policy name: 1 to 128 letters, digits and +=,.@_-",
            ));
        }
        let path = iam_path(&req.path)?;
        if path != "/" || !req.description.is_empty() {
            self.require_level(LEVEL_IAM_API, "a policy path or description")?;
        }
        if req.shared && !req.tenant.is_empty() {
            return Err(Status::invalid_argument(
                "only system policies can be shared",
            ));
        }
        let name = iam_key(&req.tenant, &plain);
        if req.policy_json.trim().is_empty() {
            return Err(Status::invalid_argument("Policy JSON is required"));
        }
        // Validate that policy_json is valid JSON
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("Invalid JSON in policy document"));
        }

        if self.iam_policies.read().contains_key(&name) {
            return Err(Status::already_exists(format!(
                "Policy '{}' already exists",
                name
            )));
        }
        let now = Self::current_timestamp();
        let policy = PolicyObject {
            name: plain,
            policy_json: req.policy_json,
            created_at: now,
            updated_at: now,
            tenant: req.tenant,
            shared: req.shared,
            path: stored_path(&path),
            policy_id: if self.active_level() >= LEVEL_IAM_API {
                iam_id("ANPA")
            } else {
                String::new()
            },
            description: req.description,
        };
        let bytes = policy.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IamPolicies,
                    key: name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-iam-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("policy already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_iam_policy(&name, &policy.encode_to_vec());
        }

        self.iam_policies
            .write()
            .insert(name.clone(), policy.clone());
        info!("Created IAM policy '{}'", name);
        Ok(Response::new(CreatePolicyResponse {
            policy: Some(policy),
        }))
    }

    pub(crate) async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let name = request.into_inner().name;
        let map = self.iam_policies.read();
        match map.get(&name) {
            Some(policy) => Ok(Response::new(GetPolicyResponse {
                policy: Some(policy.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetPolicyResponse {
                policy: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let map = self.iam_policies.read();
        let policies: Vec<PolicyObject> = map.values().cloned().collect();
        Ok(Response::new(ListPoliciesResponse { policies }))
    }

    pub(crate) async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let name = request.into_inner().name;
        // Snapshot current state: policy row + every attachment row that
        // references this policy. The whole mutation lands as one atomic
        // MultiCas — a crash mid-delete can't leave orphan attachments.
        let (expected_policy_bytes, attachment_transitions) = {
            let policies = self.iam_policies.read();
            let Some(current) = policies.get(&name) else {
                return Ok(Response::new(DeletePolicyResponse { success: false }));
            };
            let expected = current.encode_to_vec();
            #[allow(clippy::type_complexity)] // was inside #[async_trait], which clippy did not see
            let mut transitions: Vec<(String, Vec<u8>, Option<Vec<u8>>, Vec<String>)> = Vec::new();
            let atts = self.policy_attachments.read();
            for (key, policy_names) in atts.iter() {
                if policy_names.contains(&name) {
                    let before = policy_names.clone();
                    let after: Vec<String> = policy_names
                        .iter()
                        .filter(|p| *p != &name)
                        .cloned()
                        .collect();
                    let old_bytes = before.join(",").into_bytes();
                    let new_bytes = if after.is_empty() {
                        None
                    } else {
                        Some(after.join(",").into_bytes())
                    };
                    transitions.push((key.clone(), old_bytes, new_bytes, after));
                }
            }
            (expected, transitions)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(1 + attachment_transitions.len());
            ops.push(CasOp {
                table: CasTable::IamPolicies,
                key: name.clone(),
                expected: Some(expected_policy_bytes),
                new_value: None,
            });
            for (key, old, new, _) in &attachment_transitions {
                ops.push(CasOp {
                    table: CasTable::PolicyAttachments,
                    key: key.clone(),
                    expected: Some(old.clone()),
                    new_value: new.clone(),
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-iam-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "policy or attachment changed mid-delete; retry (conflicts at ops {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for delete_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iam_policy(&name);
            for (key, _, new, after) in &attachment_transitions {
                if new.is_some() {
                    store.put_policy_attachment(key, &after.join(","));
                } else {
                    store.delete_policy_attachment(key);
                }
            }
        }

        // Mirror into in-memory caches.
        self.iam_policies.write().remove(&name);
        {
            let mut atts = self.policy_attachments.write();
            for (key, _, _, after) in attachment_transitions {
                if after.is_empty() {
                    atts.remove(&key);
                } else {
                    atts.insert(key, after);
                }
            }
        }
        info!("Deleted IAM policy '{}'", name);
        Ok(Response::new(DeletePolicyResponse { success: true }))
    }

    pub(crate) async fn attach_policy(
        &self,
        request: Request<AttachPolicyRequest>,
    ) -> Result<Response<AttachPolicyResponse>, Status> {
        let req = request.into_inner();
        let policy_name = req.policy_name;

        // Validate the policy exists: a stored one, or an AWS managed one.
        if objectio_auth::managed::attached(&policy_name).is_none()
            && !self.iam_policies.read().contains_key(&policy_name)
        {
            return Err(Status::not_found(format!(
                "Policy '{}' not found",
                policy_name
            )));
        }

        let key = if !req.user_id.is_empty() {
            format!("user:{}", req.user_id)
        } else if !req.group_id.is_empty() {
            format!("group:{}", req.group_id)
        } else if !req.role_name.is_empty() {
            format!("role:{}", req.role_name)
        } else {
            return Err(Status::invalid_argument(
                "One of user_id, group_id or role_name is required",
            ));
        };

        // Snapshot current attachments under a read lock, compute the
        // transition, then CAS. Idempotent: if the policy is already
        // attached, no-op returns success without a Raft round-trip.
        let (expected_bytes, new_policies_vec) = {
            let atts = self.policy_attachments.read();
            let current: Vec<String> = atts.get(&key).cloned().unwrap_or_default();
            if current.contains(&policy_name) {
                return Ok(Response::new(AttachPolicyResponse { success: true }));
            }
            let old_bytes = if current.is_empty() {
                None
            } else {
                Some(current.join(",").into_bytes())
            };
            let mut after = current;
            after.push(policy_name.clone());
            (old_bytes, after)
        };
        let new_bytes = new_policies_vec.join(",").into_bytes();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::PolicyAttachments,
                    key: key.clone(),
                    expected: expected_bytes,
                    new_value: Some(new_bytes),
                }],
                requested_by: "attach-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("attachment changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for attach_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_policy_attachment(&key, &new_policies_vec.join(","));
        }

        self.policy_attachments
            .write()
            .insert(key.clone(), new_policies_vec);
        info!("Attached policy '{}' to '{}'", policy_name, key);
        Ok(Response::new(AttachPolicyResponse { success: true }))
    }

    pub(crate) async fn detach_policy(
        &self,
        request: Request<DetachPolicyRequest>,
    ) -> Result<Response<DetachPolicyResponse>, Status> {
        let req = request.into_inner();
        let policy_name = req.policy_name;

        let key = if !req.user_id.is_empty() {
            format!("user:{}", req.user_id)
        } else if !req.group_id.is_empty() {
            format!("group:{}", req.group_id)
        } else if !req.role_name.is_empty() {
            format!("role:{}", req.role_name)
        } else {
            return Err(Status::invalid_argument(
                "One of user_id, group_id or role_name is required",
            ));
        };

        // Compute the transition under a read lock.
        let (expected_bytes, new_after) = {
            let atts = self.policy_attachments.read();
            let Some(current) = atts.get(&key).cloned() else {
                return Ok(Response::new(DetachPolicyResponse { success: false }));
            };
            if !current.contains(&policy_name) {
                return Ok(Response::new(DetachPolicyResponse { success: false }));
            }
            let old_bytes = current.join(",").into_bytes();
            let after: Vec<String> = current.into_iter().filter(|p| p != &policy_name).collect();
            (old_bytes, after)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let new_value = if new_after.is_empty() {
                None
            } else {
                Some(new_after.join(",").into_bytes())
            };
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::PolicyAttachments,
                    key: key.clone(),
                    expected: Some(expected_bytes),
                    new_value,
                }],
                requested_by: "detach-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("attachment changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for detach_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            if new_after.is_empty() {
                store.delete_policy_attachment(&key);
            } else {
                store.put_policy_attachment(&key, &new_after.join(","));
            }
        }

        let mut attachments = self.policy_attachments.write();
        if new_after.is_empty() {
            attachments.remove(&key);
        } else {
            attachments.insert(key.clone(), new_after);
        }
        info!("Detached policy '{}' from '{}'", policy_name, key);
        let removed = true;
        Ok(Response::new(DetachPolicyResponse { success: removed }))
    }

    pub(crate) async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let req = request.into_inner();
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("Invalid JSON in policy document"));
        }
        let old = self
            .iam_policies
            .read()
            .get(&req.name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("Policy '{}' not found", req.name)))?;
        let mut new = old.clone();
        new.policy_json = req.policy_json;
        new.updated_at = Self::current_timestamp();
        self.cas_one(
            objectio_meta_store::CasTable::IamPolicies,
            &req.name,
            Some(old.encode_to_vec()),
            Some(new.encode_to_vec()),
            "update-iam-policy",
        )
        .await?;
        self.iam_policies
            .write()
            .insert(req.name.clone(), new.clone());
        info!("Updated IAM policy '{}'", req.name);
        Ok(Response::new(UpdatePolicyResponse { policy: Some(new) }))
    }

    pub(crate) async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<UpdateUserResponse>, Status> {
        let req = request.into_inner();
        let old = self
            .users
            .read()
            .get(&req.user_id)
            .cloned()
            .filter(|u| u.status != UserStatus::UserDeleted as i32)
            .ok_or_else(|| Status::not_found("user not found"))?;
        let mut new = old.clone();
        if let Some(status) = req.status {
            if status != UserStatus::UserActive as i32 && status != UserStatus::UserSuspended as i32
            {
                return Err(Status::invalid_argument(
                    "status must be ACTIVE or SUSPENDED",
                ));
            }
            new.status = status;
        }
        if let Some(name) = req.display_name {
            if name.is_empty() {
                return Err(Status::invalid_argument("display_name is required"));
            }
            if self.user_name_taken(&name, &old.user_id) {
                return Err(Status::already_exists("user with this name already exists"));
            }
            new.display_name = name;
        }
        if let Some(email) = req.email {
            new.email = email;
        }
        if let Some(path) = req.path {
            let path = iam_path(&path)?;
            if path != shown_path(&old.path) {
                self.require_level(LEVEL_IAM_API, "a user path")?;
            }
            new.path = stored_path(&path);
        }
        // The ARN names the user by path and name, and follows them. The
        // system admin is known by its ARN, so it keeps both.
        let arn = user_arn(&new.tenant, &new.path, &new.display_name);
        if arn != old.arn {
            if old.arn == "arn:objectio:iam::user/admin" {
                return Err(Status::failed_precondition(
                    "the system admin's name and path can't change",
                ));
            }
            new.arn = arn;
        }
        let enc = |u: &StoredUser| -> Result<Vec<u8>, Box<Status>> {
            objectio_meta_store::record::serialize(u)
                .map_err(|e| Box::new(Status::internal(format!("user encode: {e}"))))
        };
        self.cas_one(
            objectio_meta_store::CasTable::Users,
            &req.user_id,
            Some(enc(&old).map_err(|e| *e)?),
            Some(enc(&new).map_err(|e| *e)?),
            "update-user",
        )
        .await?;
        self.users.write().insert(req.user_id.clone(), new.clone());
        info!("Updated user {} (status {})", req.user_id, new.status);
        Ok(Response::new(UpdateUserResponse {
            user: Some(user_meta(&new)),
        }))
    }

    pub(crate) async fn update_access_key(
        &self,
        request: Request<UpdateAccessKeyRequest>,
    ) -> Result<Response<UpdateAccessKeyResponse>, Status> {
        let req = request.into_inner();
        if req.status != KeyStatus::KeyActive as i32 && req.status != KeyStatus::KeyInactive as i32
        {
            return Err(Status::invalid_argument(
                "status must be ACTIVE or INACTIVE",
            ));
        }
        let old = self
            .access_keys
            .read()
            .get(&req.access_key_id)
            .cloned()
            .ok_or_else(|| Status::not_found("access key not found"))?;
        // A deleted user's keys stay off.
        if req.status == KeyStatus::KeyActive as i32
            && self
                .users
                .read()
                .get(&old.user_id)
                .is_none_or(|u| u.status == UserStatus::UserDeleted as i32)
        {
            return Err(Status::failed_precondition("the key's user is deleted"));
        }
        let mut new = old.clone();
        new.status = req.status;
        let enc = |k: &StoredAccessKey| -> Result<Vec<u8>, Box<Status>> {
            objectio_meta_store::record::serialize(k)
                .map_err(|e| Box::new(Status::internal(format!("key encode: {e}"))))
        };
        self.cas_one(
            objectio_meta_store::CasTable::AccessKeys,
            &req.access_key_id,
            Some(enc(&old).map_err(|e| *e)?),
            Some(enc(&new).map_err(|e| *e)?),
            "update-access-key",
        )
        .await?;
        self.access_keys
            .write()
            .insert(req.access_key_id.clone(), new.clone());
        info!("Access key {} status {}", req.access_key_id, new.status);
        Ok(Response::new(UpdateAccessKeyResponse {
            key: Some(AccessKeyMeta {
                access_key_id: new.access_key_id,
                secret_access_key: String::new(),
                user_id: new.user_id,
                status: new.status,
                created_at: new.created_at,
                tenant: new.tenant,
                scope: new.scope,
                operation: new.operation,
            }),
        }))
    }

    pub(crate) async fn get_sts_signing_key(
        &self,
        _request: Request<objectio_proto::metadata::GetStsSigningKeyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetStsSigningKeyResponse>, Status> {
        const TABLE: &str = "cluster_secrets";
        const KEY: &str = "sts-signing-key";
        let read = || {
            self.store
                .as_ref()
                .and_then(|s| s.read_named(TABLE, KEY))
                .filter(|k| k.len() >= 32)
        };
        if let Some(key) = read() {
            return Ok(Response::new(
                objectio_proto::metadata::GetStsSigningKeyResponse { key },
            ));
        }
        // First use: one random key, created only if none exists, so two
        // racing creators end up with the same one.
        let mut fresh = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut fresh);
        match self
            .cas_one(
                objectio_meta_store::CasTable::Named(TABLE.into()),
                KEY,
                None,
                Some(fresh),
                "create-sts-signing-key",
            )
            .await
        {
            Ok(()) => info!("Created the cluster's STS signing key"),
            Err(e) if e.code() == tonic::Code::Aborted => {}
            Err(e) => return Err(e),
        }
        read()
            .map(|key| Response::new(objectio_proto::metadata::GetStsSigningKeyResponse { key }))
            .ok_or_else(|| Status::unavailable("STS signing key not readable yet; retry"))
    }

    pub(crate) async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        let mut role = request
            .into_inner()
            .role
            .ok_or_else(|| Status::invalid_argument("role is required"))?;
        role.name = role.name.trim().to_string();
        if role.name.is_empty()
            || !role
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
        {
            return Err(Status::invalid_argument(
                "role name: letters, digits and +=,.@_- only",
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&role.trust_policy_json).is_err() {
            return Err(Status::invalid_argument(
                "trust policy must be a JSON document",
            ));
        }
        let path = iam_path(&role.path)?;
        if path != "/" {
            self.require_level(LEVEL_IAM_API, "a role path")?;
        }
        // Names are unique per tenant, ignoring case (the key keeps the
        // case it was created with).
        let taken = self
            .store
            .as_ref()
            .map(|s| s.list_named(ROLES_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, b)| RoleObject::decode(b.as_slice()).ok())
            .any(|r| r.tenant == role.tenant && r.name.eq_ignore_ascii_case(&role.name));
        if taken {
            return Err(Status::already_exists(format!(
                "role '{}' already exists",
                role.name
            )));
        }
        let now = Self::current_timestamp();
        role.arn = role_arn(&role.tenant, &path, &role.name);
        role.path = stored_path(&path);
        role.role_id = if self.active_level() >= LEVEL_IAM_API {
            iam_id("AROA")
        } else {
            String::new()
        };
        role.created_at = now;
        role.updated_at = now;
        self.cas_one(
            objectio_meta_store::CasTable::Named(ROLES_TABLE.into()),
            &iam_key(&role.tenant, &role.name),
            None,
            Some(role.encode_to_vec()),
            "create-role",
        )
        .await
        .map_err(|e| {
            if e.code() == tonic::Code::Aborted {
                Status::already_exists(format!("role '{}' already exists", role.name))
            } else {
                e
            }
        })?;
        info!("Created role {}", role.arn);
        Ok(Response::new(CreateRoleResponse { role: Some(role) }))
    }

    pub(crate) async fn get_role(
        &self,
        request: Request<GetRoleRequest>,
    ) -> Result<Response<GetRoleResponse>, Status> {
        let role = self.role(&request.into_inner().name);
        Ok(Response::new(GetRoleResponse {
            found: role.is_some(),
            role,
        }))
    }

    pub(crate) async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        let tenant = request.into_inner().tenant;
        let roles = self
            .store
            .as_ref()
            .map(|s| s.list_named(ROLES_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, b)| RoleObject::decode(b.as_slice()).ok())
            .filter(|r| tenant.is_empty() || r.tenant == tenant)
            .collect();
        Ok(Response::new(ListRolesResponse { roles }))
    }

    pub(crate) async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<UpdateRoleResponse>, Status> {
        let req = request.into_inner();
        let old = self
            .role(&req.name)
            .ok_or_else(|| Status::not_found(format!("role '{}' not found", req.name)))?;
        let mut new = old.clone();
        if let Some(d) = req.description {
            new.description = d;
        }
        if let Some(t) = req.trust_policy_json {
            if serde_json::from_str::<serde_json::Value>(&t).is_err() {
                return Err(Status::invalid_argument(
                    "trust policy must be a JSON document",
                ));
            }
            new.trust_policy_json = t;
        }
        if let Some(m) = req.max_session_seconds {
            new.max_session_seconds = m;
        }
        new.updated_at = Self::current_timestamp();
        self.cas_one(
            objectio_meta_store::CasTable::Named(ROLES_TABLE.into()),
            &req.name,
            Some(old.encode_to_vec()),
            Some(new.encode_to_vec()),
            "update-role",
        )
        .await?;
        Ok(Response::new(UpdateRoleResponse { role: Some(new) }))
    }

    pub(crate) async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        let name = request.into_inner().name;
        let old = self
            .role(&name)
            .ok_or_else(|| Status::not_found(format!("role '{name}' not found")))?;
        // Its inline policies and attachments go with it: a role created
        // later under the same name must not inherit them.
        let principal = format!("role:{name}");
        let mut ops = vec![objectio_meta_store::CasOp {
            table: objectio_meta_store::CasTable::Named(ROLES_TABLE.into()),
            key: name.clone(),
            expected: Some(old.encode_to_vec()),
            new_value: None,
        }];
        ops.extend(self.principal_cleanup_ops(&principal));
        if !self.cas_many(ops, "delete-role").await? {
            return Err(Status::aborted("role changed since read; retry delete"));
        }
        self.forget_principal(&principal);
        info!("Deleted role {}", old.arn);
        Ok(Response::new(DeleteRoleResponse { success: true }))
    }

    /// Whether the principal an inline policy would hang off exists.
    fn principal_exists(&self, principal: &str) -> bool {
        if let Some(id) = principal.strip_prefix("user:") {
            self.users
                .read()
                .get(id)
                .is_some_and(|u| u.status != UserStatus::UserDeleted as i32)
        } else if let Some(id) = principal.strip_prefix("group:") {
            self.groups.read().contains_key(id)
        } else if let Some(key) = principal.strip_prefix("role:") {
            self.role(key).is_some()
        } else {
            false
        }
    }

    pub(crate) async fn put_inline_policy(
        &self,
        request: Request<PutInlinePolicyRequest>,
    ) -> Result<Response<PutInlinePolicyResponse>, Status> {
        let req = request.into_inner();
        self.require_level(LEVEL_IAM_API, "inline policies")?;
        if !iam_name_ok(&req.name, 128) {
            return Err(Status::invalid_argument(
                "Policy name: 1 to 128 letters, digits and +=,.@_-",
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("Invalid JSON in policy document"));
        }
        if !self.principal_exists(&req.principal) {
            return Err(Status::not_found(format!("{} not found", req.principal)));
        }
        let key = inline_policy_key(&req.principal, &req.name);
        let current = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(INLINE_POLICIES_TABLE, &key));
        let now = Self::current_timestamp();
        let created_at = current
            .as_deref()
            .and_then(|b| InlinePolicy::decode(b).ok())
            .map_or(now, |p| p.created_at);
        let policy = InlinePolicy {
            principal: req.principal,
            name: req.name,
            policy_json: req.policy_json,
            created_at,
            updated_at: now,
        };
        self.cas_one(
            objectio_meta_store::CasTable::Named(INLINE_POLICIES_TABLE.into()),
            &key,
            current,
            Some(policy.encode_to_vec()),
            "put-inline-policy",
        )
        .await?;
        info!(
            "Put inline policy '{}' on {}",
            policy.name, policy.principal
        );
        Ok(Response::new(PutInlinePolicyResponse {
            policy: Some(policy),
        }))
    }

    pub(crate) async fn get_inline_policy(
        &self,
        request: Request<GetInlinePolicyRequest>,
    ) -> Result<Response<GetInlinePolicyResponse>, Status> {
        let req = request.into_inner();
        let policy = self
            .store
            .as_ref()
            .and_then(|s| {
                s.read_named(
                    INLINE_POLICIES_TABLE,
                    &inline_policy_key(&req.principal, &req.name),
                )
            })
            .and_then(|b| InlinePolicy::decode(b.as_slice()).ok());
        Ok(Response::new(GetInlinePolicyResponse {
            found: policy.is_some(),
            policy,
        }))
    }

    pub(crate) async fn list_inline_policies(
        &self,
        request: Request<ListInlinePoliciesRequest>,
    ) -> Result<Response<ListInlinePoliciesResponse>, Status> {
        let principal = request.into_inner().principal;
        let mut policies: Vec<InlinePolicy> = self
            .inline_policies_of(&principal)
            .into_iter()
            .map(|(_, _, p)| p)
            .collect();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Response::new(ListInlinePoliciesResponse { policies }))
    }

    pub(crate) async fn delete_inline_policy(
        &self,
        request: Request<DeleteInlinePolicyRequest>,
    ) -> Result<Response<DeleteInlinePolicyResponse>, Status> {
        let req = request.into_inner();
        let key = inline_policy_key(&req.principal, &req.name);
        let current = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(INLINE_POLICIES_TABLE, &key))
            .ok_or_else(|| {
                Status::not_found(format!(
                    "{} has no inline policy '{}'",
                    req.principal, req.name
                ))
            })?;
        self.cas_one(
            objectio_meta_store::CasTable::Named(INLINE_POLICIES_TABLE.into()),
            &key,
            Some(current),
            None,
            "delete-inline-policy",
        )
        .await?;
        info!("Deleted inline policy '{}' of {}", req.name, req.principal);
        Ok(Response::new(DeleteInlinePolicyResponse { success: true }))
    }

    pub(crate) async fn list_attached_policies(
        &self,
        request: Request<ListAttachedPoliciesRequest>,
    ) -> Result<Response<ListAttachedPoliciesResponse>, Status> {
        let req = request.into_inner();
        let key = if !req.user_id.is_empty() {
            format!("user:{}", req.user_id)
        } else if !req.group_id.is_empty() {
            format!("group:{}", req.group_id)
        } else if !req.role_name.is_empty() {
            format!("role:{}", req.role_name)
        } else {
            return Err(Status::invalid_argument(
                "One of user_id, group_id or role_name is required",
            ));
        };

        let attachments = self.policy_attachments.read();
        let policy_names = attachments.get(&key).cloned().unwrap_or_default();
        Ok(Response::new(ListAttachedPoliciesResponse { policy_names }))
    }
}

#[cfg(test)]
mod iam_api_tests {
    //! What the IAM API needs of meta: paths, case-insensitive names,
    //! renames the ARN follows, inline policies, and principals that take
    //! everything hanging off them when they go.

    use super::*;

    fn service(level: u32) -> (tempfile::TempDir, MetaService) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MetaStore::open(dir.path().join("meta.redb")).unwrap());
        let svc = MetaService::with_store(EcConfig::default(), store);
        svc.config.write().insert(
            objectio_common::version::ACTIVE_LEVEL_KEY.to_string(),
            ConfigEntry {
                key: objectio_common::version::ACTIVE_LEVEL_KEY.to_string(),
                value: level.to_string().into_bytes(),
                ..Default::default()
            },
        );
        (dir, svc)
    }

    async fn user(svc: &MetaService, name: &str, path: &str) -> Result<UserMeta, Status> {
        svc.create_user(Request::new(CreateUserRequest {
            display_name: name.to_string(),
            path: path.to_string(),
            ..Default::default()
        }))
        .await
        .map(|r| r.into_inner().user.unwrap())
    }

    const DOC: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;

    async fn put_inline(svc: &MetaService, principal: &str, name: &str) -> Result<(), Status> {
        svc.put_inline_policy(Request::new(PutInlinePolicyRequest {
            principal: principal.to_string(),
            name: name.to_string(),
            policy_json: DOC.to_string(),
        }))
        .await
        .map(drop)
    }

    async fn inline_names(svc: &MetaService, principal: &str) -> Vec<String> {
        svc.list_inline_policies(Request::new(ListInlinePoliciesRequest {
            principal: principal.to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .policies
        .into_iter()
        .map(|p| p.name)
        .collect()
    }

    #[tokio::test]
    async fn names_are_case_insensitive_and_the_arn_follows_a_rename() {
        let (_d, svc) = service(LEVEL_IAM_API);
        let alice = user(&svc, "Alice", "/team/").await.unwrap();
        assert_eq!(alice.arn, "arn:objectio:iam::user/team/Alice");
        assert_eq!(alice.path, "/team/");
        let again = user(&svc, "alice", "/").await.unwrap_err();
        assert_eq!(again.code(), tonic::Code::AlreadyExists);

        let renamed = svc
            .update_user(Request::new(UpdateUserRequest {
                user_id: alice.user_id.clone(),
                display_name: Some("Bob".into()),
                path: Some("/ops/".into()),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .unwrap();
        assert_eq!(renamed.arn, "arn:objectio:iam::user/ops/Bob");
        // The old name is free again.
        user(&svc, "alice", "/").await.unwrap();
        // A bad path is refused.
        let bad = user(&svc, "carol", "no-slashes").await.unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn what_level_3_adds_waits_for_the_cluster_to_reach_it() {
        let (_d, svc) = service(2);
        // The root path is what was always written.
        user(&svc, "alice", "/").await.unwrap();
        let pathed = user(&svc, "bob", "/team/").await.unwrap_err();
        assert_eq!(pathed.code(), tonic::Code::FailedPrecondition);
        let alice = svc.users.read().values().next().unwrap().user_id.clone();
        let inline = put_inline(&svc, &format!("user:{alice}"), "p")
            .await
            .unwrap_err();
        assert_eq!(inline.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn a_deleted_role_takes_its_policies_and_a_new_one_starts_empty() {
        let (_d, svc) = service(LEVEL_IAM_API);
        let role = || RoleObject {
            name: "ci".into(),
            tenant: String::new(),
            trust_policy_json: "{}".into(),
            ..Default::default()
        };
        let created = svc
            .create_role(Request::new(CreateRoleRequest { role: Some(role()) }))
            .await
            .unwrap()
            .into_inner()
            .role
            .unwrap();
        assert!(created.role_id.starts_with("AROA"));
        // Names are case-insensitive.
        let clash = svc
            .create_role(Request::new(CreateRoleRequest {
                role: Some(RoleObject {
                    name: "CI".into(),
                    ..role()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(clash.code(), tonic::Code::AlreadyExists);

        put_inline(&svc, "role:ci", "s3").await.unwrap();
        svc.attach_policy(Request::new(AttachPolicyRequest {
            policy_name: "aws:AmazonS3ReadOnlyAccess".into(),
            role_name: "ci".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        assert_eq!(inline_names(&svc, "role:ci").await, vec!["s3"]);

        svc.delete_role(Request::new(DeleteRoleRequest { name: "ci".into() }))
            .await
            .unwrap();
        let recreated = svc
            .create_role(Request::new(CreateRoleRequest { role: Some(role()) }))
            .await
            .unwrap()
            .into_inner()
            .role
            .unwrap();
        assert_ne!(recreated.role_id, created.role_id);
        assert!(inline_names(&svc, "role:ci").await.is_empty());
        let attached = svc
            .list_attached_policies(Request::new(ListAttachedPoliciesRequest {
                role_name: "ci".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .policy_names;
        assert!(attached.is_empty(), "{attached:?}");
    }

    #[tokio::test]
    async fn a_deleted_user_leaves_its_groups_and_policies() {
        let (_d, svc) = service(LEVEL_IAM_API);
        let alice = user(&svc, "alice", "/").await.unwrap();
        let group = svc
            .create_group(Request::new(CreateGroupRequest {
                group_name: "devs".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .group
            .unwrap();
        svc.add_user_to_group(Request::new(AddUserToGroupRequest {
            group_id: group.group_id.clone(),
            user_id: alice.user_id.clone(),
        }))
        .await
        .unwrap();
        let principal = format!("user:{}", alice.user_id);
        put_inline(&svc, &principal, "p").await.unwrap();

        svc.delete_user(Request::new(DeleteUserRequest {
            user_id: alice.user_id.clone(),
        }))
        .await
        .unwrap();
        assert!(inline_names(&svc, &principal).await.is_empty());
        assert!(
            svc.groups.read()[&group.group_id]
                .member_user_ids
                .is_empty()
        );
        // An inline policy needs a live principal.
        let orphan = put_inline(&svc, &principal, "p").await.unwrap_err();
        assert_eq!(orphan.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn a_group_renamed_keeps_its_id_and_its_arn_follows() {
        let (_d, svc) = service(LEVEL_IAM_API);
        let create = |name: &str| {
            svc.create_group(Request::new(CreateGroupRequest {
                group_name: name.into(),
                tenant: String::new(),
                path: "/a/".into(),
            }))
        };
        let devs = create("devs").await.unwrap().into_inner().group.unwrap();
        create("ops").await.unwrap();
        assert_eq!(devs.arn, "arn:obio:iam::objectio:group/a/devs");
        let clash = svc
            .update_group(Request::new(UpdateGroupRequest {
                group_id: devs.group_id.clone(),
                group_name: Some("OPS".into()),
                path: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(clash.code(), tonic::Code::AlreadyExists);
        let moved = svc
            .update_group(Request::new(UpdateGroupRequest {
                group_id: devs.group_id.clone(),
                group_name: Some("builders".into()),
                path: Some("/b/".into()),
            }))
            .await
            .unwrap()
            .into_inner()
            .group
            .unwrap();
        assert_eq!(moved.group_id, devs.group_id);
        assert_eq!(moved.arn, "arn:obio:iam::objectio:group/b/builders");
        assert_eq!(moved.path, "/b/");
    }

    #[tokio::test]
    async fn only_known_aws_managed_policies_attach() {
        let (_d, svc) = service(LEVEL_IAM_API);
        let alice = user(&svc, "alice", "/").await.unwrap();
        let attach = |name: &str| {
            svc.attach_policy(Request::new(AttachPolicyRequest {
                policy_name: name.into(),
                user_id: alice.user_id.clone(),
                ..Default::default()
            }))
        };
        attach("aws:IAMReadOnlyAccess").await.unwrap();
        let unknown = attach("aws:NoSuchPolicy").await.unwrap_err();
        assert_eq!(unknown.code(), tonic::Code::NotFound);
        // A stored policy can't take a name that looks like one.
        let named = svc
            .create_policy(Request::new(CreatePolicyRequest {
                name: "aws:IAMReadOnlyAccess".into(),
                policy_json: DOC.into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(named.code(), tonic::Code::InvalidArgument);
    }
}
