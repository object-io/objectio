//! Bucket policy structures and evaluation
//!
//! Implements S3-compatible bucket policies with IAM-like permissions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A bucket policy document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BucketPolicy {
    /// Policy version (typically "2012-10-17")
    #[serde(default = "default_version")]
    pub version: String,
    /// Policy ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Policy statements. IAM takes one statement on its own as well as a
    /// list of them.
    #[serde(rename = "Statement", deserialize_with = "one_or_many")]
    pub statements: Vec<PolicyStatement>,
}

/// One statement, or a list of them.
fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<PolicyStatement>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_object() {
        serde_json::from_value(value)
            .map(|s| vec![s])
            .map_err(D::Error::custom)
    } else {
        serde_json::from_value(value).map_err(D::Error::custom)
    }
}

fn default_version() -> String {
    "2012-10-17".to_string()
}

impl Default for BucketPolicy {
    fn default() -> Self {
        Self {
            version: default_version(),
            id: None,
            statements: Vec::new(),
        }
    }
}

impl BucketPolicy {
    /// Create a new empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a policy from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let policy: Self = serde_json::from_str(json)?;
        // Principal and NotPrincipal are exclusive; NotPrincipal only denies.
        let raw: serde_json::Value = serde_json::from_str(json)?;
        let statements = match raw.get("Statement") {
            Some(serde_json::Value::Array(a)) => a.clone(),
            Some(one) => vec![one.clone()],
            None => Vec::new(),
        };
        for st in &statements {
            if st.get("NotPrincipal").is_some() {
                if st.get("Principal").is_some() {
                    return Err(serde::de::Error::custom(
                        "a statement can't have both Principal and NotPrincipal",
                    ));
                }
                if st.get("Effect").and_then(|e| e.as_str()) != Some("Deny") {
                    return Err(serde::de::Error::custom(
                        "NotPrincipal is allowed only with \"Effect\": \"Deny\"",
                    ));
                }
            }
        }
        if let Some(op) = policy
            .statements
            .iter()
            .filter_map(|s| s.condition.as_ref())
            .find_map(Conditions::unknown_operator)
        {
            return Err(serde::de::Error::custom(format!(
                "unknown condition operator {op:?}"
            )));
        }
        Ok(policy)
    }

    /// Whether this policy makes the bucket public, as AWS defines it: some
    /// statement allows everyone (`"*"`) and no condition pins it to fixed
    /// callers (source IPs short of the whole internet, source ARNs or
    /// accounts, VPCs, organisations, user ids).
    pub fn is_public(&self) -> bool {
        self.statements
            .iter()
            .any(|st| st.effect == Effect::Allow && st.principal.is_everyone() && !st.is_pinned())
    }

    /// This policy as it applies to an anonymous caller: every Deny, and
    /// only the Allows that name everyone. A grant to particular principals
    /// never reaches someone who presented no identity.
    #[must_use]
    pub fn for_anonymous(&self) -> Self {
        Self {
            version: self.version.clone(),
            id: self.id.clone(),
            statements: self
                .statements
                .iter()
                .filter(|st| st.effect == Effect::Deny || st.principal.is_everyone())
                .cloned()
                .collect(),
        }
    }

    /// This policy without its grants to everyone: what still holds for a
    /// caller that `RestrictPublicBuckets` keeps from public grants.
    #[must_use]
    pub fn without_public_grants(&self) -> Self {
        Self {
            version: self.version.clone(),
            id: self.id.clone(),
            statements: self
                .statements
                .iter()
                .filter(|st| st.effect == Effect::Deny || !st.principal.is_everyone())
                .cloned()
                .collect(),
        }
    }

    /// A role's trust policy. As in AWS its statements name no `Resource`:
    /// the resource is the role it is attached to, so one is implied.
    pub fn from_trust_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut raw: serde_json::Value = serde_json::from_str(json)?;
        let imply = |st: &mut serde_json::Value| {
            if let Some(obj) = st.as_object_mut()
                && !obj.contains_key("Resource")
                && !obj.contains_key("NotResource")
            {
                obj.insert("Resource".to_string(), serde_json::json!("*"));
            }
        };
        match raw.get_mut("Statement") {
            Some(serde_json::Value::Array(a)) => a.iter_mut().for_each(imply),
            Some(one) => imply(one),
            None => {}
        }
        Self::from_json(&raw.to_string())
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Add a statement to the policy
    pub fn add_statement(&mut self, statement: PolicyStatement) {
        self.statements.push(statement);
    }
}

/// A policy statement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatement {
    /// Statement ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Effect: Allow or Deny
    pub effect: Effect,
    /// Principal: who this statement applies to. Defaults to `*` so that
    /// AWS-shape inline IAM policies (which omit Principal — the implicit
    /// principal is whoever the policy is attached to) parse without
    /// having to be hand-edited.
    #[serde(default)]
    pub principal: Principal,
    /// NotPrincipal: the statement applies to everyone *but* these. Only on
    /// a Deny, as AWS allows it. It used to be ignored, and Principal
    /// defaulted to everyone: an "Allow, NotPrincipal X" allowed everyone,
    /// a "Deny, NotPrincipal admins" denied the admins too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_principal: Option<Principal>,
    /// Actions this statement covers
    pub action: ActionList,
    /// Resources this statement covers
    pub resource: ResourceList,
    /// Conditions for this statement (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<Conditions>,
}

impl PolicyStatement {
    /// Whether a condition confines this statement to fixed callers, so that
    /// allowing `"*"` does not make it public.
    fn is_pinned(&self) -> bool {
        const PINNING_KEYS: &[&str] = &[
            "aws:sourcearn",
            "aws:sourcevpc",
            "aws:sourcevpce",
            "aws:sourceaccount",
            "aws:sourceowner",
            "aws:principalorgid",
            "aws:principalaccount",
            "aws:principalarn",
            "aws:userid",
            "aws:username",
            "aws:sourceip",
        ];
        let Some(conditions) = &self.condition else {
            return false;
        };
        conditions.0.iter().any(|(op, keys)| {
            // Only a positive, exact match pins: "not this one" or a
            // wildcard pattern still lets strangers in.
            let op = op.trim_end_matches("IfExists");
            let exact = matches!(
                op,
                "StringEquals" | "StringEqualsIgnoreCase" | "ArnEquals" | "IpAddress"
            ) || (op == "ArnLike" || op == "StringLike");
            exact
                && keys.iter().any(|(key, values)| {
                    let key = key.to_ascii_lowercase();
                    PINNING_KEYS.contains(&key.as_str())
                        && values.as_vec().iter().all(|v| {
                            !v.contains('*')
                                && !(key == "aws:sourceip" && (v.ends_with("/0") || v.is_empty()))
                        })
                })
        })
    }

    /// Create a new Allow statement
    pub fn allow() -> PolicyStatementBuilder {
        PolicyStatementBuilder::new(Effect::Allow)
    }

    /// Create a new Deny statement
    pub fn deny() -> PolicyStatementBuilder {
        PolicyStatementBuilder::new(Effect::Deny)
    }
}

/// Builder for policy statements
pub struct PolicyStatementBuilder {
    effect: Effect,
    sid: Option<String>,
    principal: Option<Principal>,
    actions: Vec<String>,
    resources: Vec<String>,
    conditions: Option<Conditions>,
}

impl PolicyStatementBuilder {
    fn new(effect: Effect) -> Self {
        Self {
            effect,
            sid: None,
            principal: None,
            actions: Vec::new(),
            resources: Vec::new(),
            conditions: None,
        }
    }

    pub fn sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = Some(sid.into());
        self
    }

    pub fn principal_any(mut self) -> Self {
        self.principal = Some(Principal::Wildcard);
        self
    }

    pub fn principal_obio(mut self, arns: Vec<String>) -> Self {
        self.principal = Some(Principal::OBIO(arns));
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.actions.push(action.into());
        self
    }

    pub fn actions(mut self, actions: Vec<String>) -> Self {
        self.actions.extend(actions);
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.push(resource.into());
        self
    }

    pub fn resources(mut self, resources: Vec<String>) -> Self {
        self.resources.extend(resources);
        self
    }

    pub fn condition(mut self, conditions: Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    pub fn build(self) -> PolicyStatement {
        PolicyStatement {
            not_principal: None,
            sid: self.sid,
            effect: self.effect,
            principal: self.principal.unwrap_or(Principal::Wildcard),
            action: ActionList(self.actions),
            resource: ResourceList(self.resources),
            condition: self.conditions,
        }
    }
}

/// Policy effect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

/// Principal specification
#[derive(Debug, Clone, Default)]
pub enum Principal {
    /// Wildcard ("*") - applies to everyone
    #[default]
    Wildcard,
    /// Specific OBIO principals (user/role ARNs)
    OBIO(Vec<String>),
}

impl Principal {
    /// Names everyone: `"*"`, `{"AWS": "*"}` or a list holding `"*"`.
    pub fn is_everyone(&self) -> bool {
        match self {
            Self::Wildcard => true,
            Self::OBIO(arns) => arns.iter().any(|a| a == "*"),
        }
    }
}

impl Serialize for Principal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Principal::Wildcard => serializer.serialize_str("*"),
            Principal::OBIO(arns) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("OBIO", arns)?;
                map.end()
            }
        }
    }
}

/// The system scope's account, in ARNs: `arn:obio:iam::objectio:role/ops`.
pub const SYSTEM_ACCOUNT: &str = "objectio";

/// An ARN in its one canonical spelling, for matching.
///
/// The same identity or resource has several spellings, and a policy may
/// use any of them:
///
/// - the partition: policies are written for S3 with `arn:aws:` ARNs
///   (every tool, tutorial and generated policy does), ObjectIO's own are
///   `arn:obio:`, and users carry `arn:objectio:` ones. All name the same
///   buckets, keys and users;
/// - a system-scope user: `arn:objectio:iam::user/<name>` has no account
///   segment at all;
/// - the system scope's account in IAM and STS ARNs: `objectio`, or empty
///   (`arn:aws:iam:::role/ops`, as the IAM API shows it).
///
/// Each becomes `arn:obio:<service>:<region>:<account>:<resource>`, with
/// the system account spelled `objectio`. Anything that isn't an ARN is
/// returned as it is.
#[must_use]
pub fn canonical_arn(arn: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let Some(rest) = arn
        .strip_prefix("arn:aws:")
        .or_else(|| arn.strip_prefix("arn:obio:"))
        .or_else(|| arn.strip_prefix("arn:objectio:"))
    else {
        return Cow::Borrowed(arn);
    };
    // A system user: "iam::user/<name>" (service, region, then the
    // resource where the account should be).
    if let Some(user) = rest.strip_prefix("iam::user/") {
        return Cow::Owned(format!("arn:obio:iam::{SYSTEM_ACCOUNT}:user/{user}"));
    }
    let mut parts = rest.splitn(4, ':');
    let (Some(service), Some(region), Some(account), Some(resource)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Cow::Owned(format!("arn:obio:{rest}"));
    };
    let system = account.is_empty() && matches!(service, "iam" | "sts");
    if arn.starts_with("arn:obio:") && !system {
        return Cow::Borrowed(arn);
    }
    let account = if system { SYSTEM_ACCOUNT } else { account };
    Cow::Owned(format!("arn:obio:{service}:{region}:{account}:{resource}"))
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct PrincipalVisitor;

        impl<'de> Visitor<'de> for PrincipalVisitor {
            type Value = Principal;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("\"*\" or {\"AWS\": [...]} or {\"OBIO\": [...]}")
            }

            fn visit_str<E>(self, value: &str) -> Result<Principal, E>
            where
                E: de::Error,
            {
                if value == "*" {
                    Ok(Principal::Wildcard)
                } else {
                    Err(de::Error::custom(format!(
                        "invalid principal string: expected \"*\", got \"{}\"",
                        value
                    )))
                }
            }

            fn visit_map<M>(self, mut map: M) -> Result<Principal, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut obio_principals: Option<Vec<String>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    // `AWS` is the spelling every S3 tool, tutorial and
                    // generated policy uses. Accepting only `OBIO` meant an
                    // otherwise-correct policy failed to parse, and a policy
                    // that fails to parse is treated as no policy at all — so
                    // the grant silently did nothing.
                    if key == "OBIO" || key == "AWS" {
                        // OBIO can be "*", a single string, or an array
                        let value: serde_json::Value = map.next_value()?;
                        match value {
                            serde_json::Value::String(s) if s == "*" => {
                                return Ok(Principal::Wildcard);
                            }
                            serde_json::Value::String(s) => {
                                obio_principals = Some(vec![s]);
                            }
                            serde_json::Value::Array(arr) => {
                                let arns: Result<Vec<String>, _> = arr
                                    .into_iter()
                                    .map(|v| {
                                        v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                                            de::Error::custom("expected string in OBIO array")
                                        })
                                    })
                                    .collect();
                                obio_principals = Some(arns?);
                            }
                            _ => {
                                return Err(de::Error::custom(
                                    "OBIO must be \"*\", string, or array",
                                ));
                            }
                        }
                    } else if key == "Service" || key == "CanonicalUser" || key == "Federated" {
                        // Principals that are never one of our users (a
                        // logging service, say): kept so the policy parses,
                        // and named so they match no user ARN.
                        let value: serde_json::Value = map.next_value()?;
                        let names: Vec<String> = match value {
                            serde_json::Value::String(s) => vec![s],
                            serde_json::Value::Array(a) => a
                                .into_iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect(),
                            _ => Vec::new(),
                        };
                        // An identity provider is named by its issuer,
                        // with or without the scheme.
                        let bare = |n: String| {
                            let n = n.trim_end_matches('/');
                            n.strip_prefix("https://")
                                .or_else(|| n.strip_prefix("http://"))
                                .unwrap_or(n)
                                .to_string()
                        };
                        obio_principals
                            .get_or_insert_with(Vec::new)
                            .extend(names.into_iter().map(|n| format!("{key}:{}", bare(n))));
                    } else {
                        // Skip unknown keys
                        let _: serde_json::Value = map.next_value()?;
                    }
                }

                obio_principals
                    .map(Principal::OBIO)
                    .ok_or_else(|| de::Error::custom("principal needs an \"AWS\" or \"OBIO\" key"))
            }
        }

        deserializer.deserialize_any(PrincipalVisitor)
    }
}

/// Helper to serialize single value or array
#[derive(Debug, Clone)]
pub struct ActionList(pub Vec<String>);

impl From<Vec<String>> for ActionList {
    fn from(v: Vec<String>) -> Self {
        Self(v)
    }
}

impl From<&str> for ActionList {
    fn from(s: &str) -> Self {
        Self(vec![s.to_string()])
    }
}

impl Serialize for ActionList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() == 1 {
            self.0[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ActionList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => Ok(ActionList(vec![s])),
            serde_json::Value::Array(arr) => {
                let strings: Result<Vec<String>, _> = arr
                    .into_iter()
                    .map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .ok_or_else(|| serde::de::Error::custom("expected string in array"))
                    })
                    .collect();
                Ok(ActionList(strings?))
            }
            _ => Err(serde::de::Error::custom(
                "expected string or array of strings",
            )),
        }
    }
}

/// Helper to serialize single value or array
#[derive(Debug, Clone)]
pub struct ResourceList(pub Vec<String>);

impl From<Vec<String>> for ResourceList {
    fn from(v: Vec<String>) -> Self {
        Self(v)
    }
}

impl From<&str> for ResourceList {
    fn from(s: &str) -> Self {
        Self(vec![s.to_string()])
    }
}

impl Serialize for ResourceList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() == 1 {
            self.0[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ResourceList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => Ok(ResourceList(vec![s])),
            serde_json::Value::Array(arr) => {
                let strings: Result<Vec<String>, _> = arr
                    .into_iter()
                    .map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .ok_or_else(|| serde::de::Error::custom("expected string in array"))
                    })
                    .collect();
                Ok(ResourceList(strings?))
            }
            _ => Err(serde::de::Error::custom(
                "expected string or array of strings",
            )),
        }
    }
}

/// Policy conditions: operator → condition key → values, as IAM writes
/// them (`{"StringEquals": {"s3:prefix": ["a/", "b/"]}}`).
///
/// Every IAM operator is understood, with the `IfExists` suffix and the
/// `ForAnyValue:` / `ForAllValues:` qualifiers. An operator that isn't
/// (see [`Conditions::unknown_operator`]) is refused when a policy is put,
/// and if one is ever met in a stored policy its statement can only deny:
/// an Allow under it never matches, a Deny under it always does. The
/// conditions used to be a fixed set of fields, so any other operator was
/// dropped on parsing, and an Allow it guarded became unconditional.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Conditions(pub std::collections::BTreeMap<String, HashMap<String, StringOrList>>);

/// The operators IAM defines, without `IfExists` or a set qualifier.
const CONDITION_OPERATORS: &[&str] = &[
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "DateEquals",
    "DateNotEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
    "Bool",
    "BinaryEquals",
    "IpAddress",
    "NotIpAddress",
    "ArnEquals",
    "ArnLike",
    "ArnNotEquals",
    "ArnNotLike",
    "Null",
];

/// An operator split into its parts: the base operator, whether `IfExists`
/// was appended, and its set qualifier.
struct Operator<'a> {
    base: &'a str,
    if_exists: bool,
    for_all: bool,
}

impl<'a> Operator<'a> {
    fn parse(name: &'a str) -> Option<Self> {
        let (for_all, rest) = if let Some(r) = name.strip_prefix("ForAllValues:") {
            (true, r)
        } else if let Some(r) = name.strip_prefix("ForAnyValue:") {
            (false, r)
        } else {
            (false, name)
        };
        let (base, if_exists) = match rest.strip_suffix("IfExists") {
            Some(b) if b != "Null" => (b, true),
            _ => (rest, false),
        };
        CONDITION_OPERATORS.contains(&base).then_some(Self {
            base,
            if_exists,
            for_all,
        })
    }

    /// A negated operator holds when nothing matches, and when the key is
    /// missing.
    fn negated(&self) -> bool {
        matches!(
            self.base,
            "StringNotEquals"
                | "StringNotEqualsIgnoreCase"
                | "StringNotLike"
                | "NumericNotEquals"
                | "DateNotEquals"
                | "NotIpAddress"
                | "ArnNotEquals"
                | "ArnNotLike"
        )
    }
}

impl Conditions {
    /// The first operator in these conditions that isn't IAM's, if any.
    pub fn unknown_operator(&self) -> Option<&str> {
        self.0
            .keys()
            .find(|op| Operator::parse(op).is_none())
            .map(String::as_str)
    }
}

/// String or list of strings (for conditions). Booleans and numbers are
/// taken as their text, as IAM takes them (`"Bool": {"k": true}`); they
/// used to fail the whole policy's parse.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum StringOrList {
    Single(String),
    List(Vec<String>),
}

impl<'de> Deserialize<'de> for StringOrList {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        fn text(v: &serde_json::Value) -> Option<String> {
            match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Bool(b) => Some(b.to_string()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            }
        }
        let v = serde_json::Value::deserialize(d)?;
        match &v {
            serde_json::Value::Array(items) => items
                .iter()
                .map(|i| text(i).ok_or_else(|| serde::de::Error::custom("condition value")))
                .collect::<Result<Vec<_>, _>>()
                .map(StringOrList::List),
            other => text(other)
                .map(StringOrList::Single)
                .ok_or_else(|| serde::de::Error::custom("condition value")),
        }
    }
}

impl StringOrList {
    pub fn as_vec(&self) -> Vec<&str> {
        match self {
            StringOrList::Single(s) => vec![s.as_str()],
            StringOrList::List(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Explicitly allowed
    Allow,
    /// Explicitly denied
    Deny,
    /// No matching statement (implicit deny)
    ImplicitDeny,
}

/// Detailed policy evaluation result with explanation.
#[derive(Debug, Clone)]
pub struct PolicyExplanation {
    /// The decision: Allow, Deny, or ImplicitDeny
    pub decision: PolicyDecision,
    /// The statement that caused the decision (None for ImplicitDeny)
    pub matched_statement: Option<MatchedStatement>,
}

/// Information about the statement that matched.
#[derive(Debug, Clone)]
pub struct MatchedStatement {
    /// Statement ID (if present in the policy)
    pub sid: Option<String>,
    /// Effect of the matched statement
    pub effect: Effect,
    /// The policy source (e.g., "catalog", "namespace:prod", "table:events")
    pub source: String,
}

/// Context for policy evaluation
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// User ARN making the request
    pub user_arn: String,
    /// Action being performed (e.g., "s3:GetObject")
    pub action: String,
    /// Resource ARN (e.g., "arn:obio:s3:::bucket/key")
    pub resource: String,
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    /// Additional context variables (single-valued)
    pub variables: HashMap<String, String>,
    /// Multi-valued context variables (e.g., `obio:PrincipalGroup`)
    pub multi_variables: HashMap<String, Vec<String>>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(
        user_arn: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            user_arn: user_arn.into(),
            action: action.into(),
            resource: resource.into(),
            source_ip: None,
            variables: HashMap::new(),
            multi_variables: HashMap::new(),
        }
    }

    /// Set source IP
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Add a context variable
    pub fn with_variable(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.insert(key.into(), value.into());
        self
    }

    /// Add a multi-valued context variable (e.g., `obio:PrincipalGroup`)
    pub fn with_multi_variable(mut self, key: impl Into<String>, values: Vec<String>) -> Self {
        self.multi_variables.insert(key.into(), values);
        self
    }
}

/// Policy evaluator
pub struct PolicyEvaluator;

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a policy against a request context
    pub fn evaluate(&self, policy: &BucketPolicy, context: &RequestContext) -> PolicyDecision {
        let mut explicit_deny = false;
        let mut explicit_allow = false;

        for statement in &policy.statements {
            // Check if statement applies to this request
            let principal_applies = match &statement.not_principal {
                Some(excepted) => !self.matches_principal(excepted, &context.user_arn),
                None => self.matches_principal(&statement.principal, &context.user_arn),
            };
            if !principal_applies {
                continue;
            }
            if !self.matches_action(&statement.action, &context.action) {
                continue;
            }
            if !self.matches_resource(&statement.resource, &context.resource) {
                continue;
            }
            if !self.matches_conditions(&statement.condition, context, statement.effect) {
                continue;
            }

            // Statement matches - record effect
            match statement.effect {
                Effect::Deny => explicit_deny = true,
                Effect::Allow => explicit_allow = true,
            }
        }

        // Deny takes precedence over Allow
        if explicit_deny {
            PolicyDecision::Deny
        } else if explicit_allow {
            PolicyDecision::Allow
        } else {
            PolicyDecision::ImplicitDeny
        }
    }

    /// Evaluate a policy against a request context with detailed explanation.
    ///
    /// Returns the decision and the statement that caused it.
    pub fn evaluate_with_explanation(
        &self,
        policy: &BucketPolicy,
        context: &RequestContext,
        source: &str,
    ) -> PolicyExplanation {
        let mut deny_stmt: Option<&PolicyStatement> = None;
        let mut allow_stmt: Option<&PolicyStatement> = None;

        for statement in &policy.statements {
            let principal_applies = match &statement.not_principal {
                Some(excepted) => !self.matches_principal(excepted, &context.user_arn),
                None => self.matches_principal(&statement.principal, &context.user_arn),
            };
            if !principal_applies {
                continue;
            }
            if !self.matches_action(&statement.action, &context.action) {
                continue;
            }
            if !self.matches_resource(&statement.resource, &context.resource) {
                continue;
            }
            if !self.matches_conditions(&statement.condition, context, statement.effect) {
                continue;
            }

            match statement.effect {
                Effect::Deny => {
                    if deny_stmt.is_none() {
                        deny_stmt = Some(statement);
                    }
                }
                Effect::Allow => {
                    if allow_stmt.is_none() {
                        allow_stmt = Some(statement);
                    }
                }
            }
        }

        if let Some(stmt) = deny_stmt {
            PolicyExplanation {
                decision: PolicyDecision::Deny,
                matched_statement: Some(MatchedStatement {
                    sid: stmt.sid.clone(),
                    effect: Effect::Deny,
                    source: source.to_string(),
                }),
            }
        } else if let Some(stmt) = allow_stmt {
            PolicyExplanation {
                decision: PolicyDecision::Allow,
                matched_statement: Some(MatchedStatement {
                    sid: stmt.sid.clone(),
                    effect: Effect::Allow,
                    source: source.to_string(),
                }),
            }
        } else {
            PolicyExplanation {
                decision: PolicyDecision::ImplicitDeny,
                matched_statement: None,
            }
        }
    }

    /// Check if principal matches
    fn matches_principal(&self, principal: &Principal, user_arn: &str) -> bool {
        match principal {
            Principal::Wildcard => true,
            Principal::OBIO(arns) => arns.iter().any(|arn| {
                if arn == "*" {
                    true
                } else {
                    self.matches_pattern(&canonical_arn(arn), &canonical_arn(user_arn))
                }
            }),
        }
    }

    /// Check if action matches
    fn matches_action(&self, actions: &ActionList, request_action: &str) -> bool {
        // Action names are case-insensitive, as in IAM. "s3:*" is a
        // service's wildcard, not everything: it used to short-circuit to
        // true, which made an S3 grant also grant every IAM and STS action.
        let request_action = request_action.to_ascii_lowercase();
        actions.0.iter().any(|action| {
            action == "*" || self.matches_pattern(&action.to_ascii_lowercase(), &request_action)
        })
    }

    /// Check if resource matches
    fn matches_resource(&self, resources: &ResourceList, request_resource: &str) -> bool {
        resources.0.iter().any(|resource| {
            self.matches_pattern(&canonical_arn(resource), &canonical_arn(request_resource))
        })
    }

    /// Whether a statement's conditions hold for the request: every
    /// operator, and for each every key (IAM's AND), with any of a key's
    /// values matching (OR).
    fn matches_conditions(
        &self,
        conditions: &Option<Conditions>,
        context: &RequestContext,
        effect: Effect,
    ) -> bool {
        let Some(conditions) = conditions else {
            return true;
        };
        for (name, keys) in &conditions.0 {
            let Some(op) = Operator::parse(name) else {
                // Not understood: fail toward denying.
                return effect == Effect::Deny;
            };
            for (key, expected) in keys {
                if !self.matches_condition(&op, key, &expected.as_vec(), context) {
                    return false;
                }
            }
        }
        true
    }

    /// One operator on one condition key.
    fn matches_condition(
        &self,
        op: &Operator<'_>,
        key: &str,
        expected: &[&str],
        context: &RequestContext,
    ) -> bool {
        let actuals = self.get_condition_values(key, context);
        if op.base == "Null" {
            // "true": the key must be absent; "false": present.
            let want_absent = expected.iter().any(|e| e.eq_ignore_ascii_case("true"));
            return actuals.is_empty() == want_absent;
        }
        if actuals.is_empty() {
            return op.if_exists || op.negated() || op.for_all;
        }
        let one = |actual: &str| {
            expected
                .iter()
                .any(|e| self.condition_value_matches(op.base, e, actual))
        };
        if op.negated() {
            // Holds when no request value matches a policy value.
            let positive = |actual: &str| {
                expected
                    .iter()
                    .any(|e| self.condition_value_matches(op.base, e, actual))
            };
            return if op.for_all {
                actuals.iter().all(|a| !positive(a))
            } else {
                !actuals.iter().any(|a| positive(a))
            };
        }
        if op.for_all {
            actuals.iter().all(|a| one(a))
        } else {
            actuals.iter().any(|a| one(a))
        }
    }

    /// Whether `actual` matches policy value `expected` under `base`.
    /// Negated operators compare as their positive form; the caller negates.
    fn condition_value_matches(&self, base: &str, expected: &str, actual: &str) -> bool {
        let number = |v: &str| v.trim().parse::<f64>().ok();
        let date = |v: &str| {
            chrono::DateTime::parse_from_rfc3339(v)
                .map(|d| d.timestamp())
                .ok()
                .or_else(|| v.trim().parse::<i64>().ok())
        };
        let cmp_num = |f: fn(f64, f64) -> bool| {
            number(actual)
                .zip(number(expected))
                .is_some_and(|(a, e)| f(a, e))
        };
        let cmp_date = |f: fn(i64, i64) -> bool| {
            date(actual)
                .zip(date(expected))
                .is_some_and(|(a, e)| f(a, e))
        };
        match base {
            "StringEquals" | "StringNotEquals" | "ArnEquals" | "ArnNotEquals" | "BinaryEquals" => {
                actual == expected
            }
            "StringEqualsIgnoreCase" | "StringNotEqualsIgnoreCase" => {
                actual.eq_ignore_ascii_case(expected)
            }
            "StringLike" | "StringNotLike" | "ArnLike" | "ArnNotLike" => {
                self.matches_pattern(expected, actual)
            }
            "Bool" => actual.eq_ignore_ascii_case(expected),
            "NumericEquals" | "NumericNotEquals" => cmp_num(|a, e| (a - e).abs() < f64::EPSILON),
            "NumericLessThan" => cmp_num(|a, e| a < e),
            "NumericLessThanEquals" => cmp_num(|a, e| a <= e),
            "NumericGreaterThan" => cmp_num(|a, e| a > e),
            "NumericGreaterThanEquals" => cmp_num(|a, e| a >= e),
            "DateEquals" | "DateNotEquals" => cmp_date(|a, e| a == e),
            "DateLessThan" => cmp_date(|a, e| a < e),
            "DateLessThanEquals" => cmp_date(|a, e| a <= e),
            "DateGreaterThan" => cmp_date(|a, e| a > e),
            "DateGreaterThanEquals" => cmp_date(|a, e| a >= e),
            "IpAddress" | "NotIpAddress" => actual
                .parse::<IpAddr>()
                .is_ok_and(|ip| self.ip_matches_cidr(&ip, expected)),
            _ => false,
        }
    }

    /// Get condition value from context (single-valued).
    fn get_condition_value(&self, key: &str, context: &RequestContext) -> Option<String> {
        match key {
            "aws:SourceIp" => context.source_ip.map(|ip| ip.to_string()),
            "aws:username" => Some(context.user_arn.clone()),
            "s3:prefix" => context.variables.get("s3:prefix").cloned(),
            "obio:CurrentTime" | "aws:CurrentTime" => Some(chrono::Utc::now().to_rfc3339()),
            "aws:EpochTime" => Some(chrono::Utc::now().timestamp().to_string()),
            _ => context.variables.get(key).cloned(),
        }
    }

    /// Get condition values from context (multi-valued).
    ///
    /// For keys like `obio:PrincipalGroup`, returns all values from
    /// `context.multi_variables`. For single-valued keys, wraps the
    /// result of `get_condition_value` in a `Vec`.
    fn get_condition_values(&self, key: &str, context: &RequestContext) -> Vec<String> {
        // Check multi_variables first (e.g., obio:PrincipalGroup)
        if let Some(values) = context.multi_variables.get(key) {
            return values.clone();
        }
        // Fall back to single-valued lookup
        self.get_condition_value(key, context).into_iter().collect()
    }

    /// Match a pattern with wildcards (* and ?)
    fn matches_pattern(&self, pattern: &str, value: &str) -> bool {
        wildcard_match(pattern, value)
    }

    /// Check if IP matches a CIDR range (e.g., `10.0.0.0/8`, `192.168.1.0/24`).
    ///
    /// Supports both IPv4 and IPv6 CIDR notation. Falls back to exact IP match
    /// if no prefix length is specified.
    fn ip_matches_cidr(&self, ip: &IpAddr, cidr: &str) -> bool {
        cidr_contains(cidr, ip)
    }
}

/// Whether `value` matches the IAM wildcard `pattern`: `*` is any run of
/// characters (none too), `?` any one character, everything else itself.
/// No regex: the pattern used to be turned into one (escaping only `.`, so
/// `+`, `(`, `[`, `|` or `$` in an ARN were read as regex syntax) and
/// compiled on every evaluation. Linear in practice: one backtrack point,
/// the last `*`.
#[must_use]
pub fn wildcard_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    // The last `*` seen, and where in `value` it started matching.
    let mut star: Option<(usize, usize)> = None;
    while j < v.len() {
        if i < p.len() && (p[i] == '?' || p[i] == v[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some((i, j));
            i += 1;
        } else if let Some((si, sj)) = star {
            // Let the last `*` take one more character.
            i = si + 1;
            j = sj + 1;
            star = Some((si, sj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == '*')
}

/// Whether `ip` is in `cidr` (`10.0.0.0/8`, `fd00::/8`, or a bare address).
/// An IPv4 address seen as IPv6 (`::ffff:10.1.2.3`) counts as IPv4.
pub fn cidr_contains(cidr: &str, ip: &IpAddr) -> bool {
    let ip = &ip.to_canonical();
    if let Some((network_str, prefix_str)) = cidr.split_once('/')
        && let Ok(prefix_len) = prefix_str.parse::<u32>()
        && let Ok(network_ip) = network_str.parse::<IpAddr>()
    {
        return match (ip, &network_ip) {
            (IpAddr::V4(addr), IpAddr::V4(net)) => {
                if prefix_len == 0 {
                    return true;
                }
                if prefix_len > 32 {
                    return false;
                }
                let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
                u32::from(*addr) & mask == u32::from(*net) & mask
            }
            (IpAddr::V6(addr), IpAddr::V6(net)) => {
                if prefix_len == 0 {
                    return true;
                }
                if prefix_len > 128 {
                    return false;
                }
                let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
                u128::from(*addr) & mask == u128::from(*net) & mask
            }
            _ => false, // IPv4 vs IPv6 mismatch
        };
    }

    // No prefix — try exact IP match
    cidr.parse::<IpAddr>().is_ok_and(|cidr_ip| ip == &cidr_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match_as_iam_says_and_nothing_else_is_special() {
        for (p, v, want) in [
            ("*", "", true),
            ("*", "anything", true),
            ("", "", true),
            ("", "a", false),
            ("s3:Get*", "s3:GetObject", true),
            ("s3:Get*", "s3:PutObject", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("a*b*c", "axxbyyc", true),
            ("a*b*c", "axxbyy", false),
            ("**", "x", true),
            ("*a", "bbba", true),
            ("*a", "bbab", false),
            // Regex syntax is literal here. The old regex form read `+` as
            // "one or more" and `(`/`[` as groups and classes.
            ("arn:obio:s3:::b/a+b", "arn:obio:s3:::b/aab", false),
            ("arn:obio:s3:::b/a+b", "arn:obio:s3:::b/a+b", true),
            ("arn:obio:s3:::b/(x|y)", "arn:obio:s3:::b/x", false),
            ("arn:obio:s3:::b/(x|y)", "arn:obio:s3:::b/(x|y)", true),
            ("arn:obio:s3:::b/[ab]", "arn:obio:s3:::b/a", false),
            ("arn:obio:s3:::b/k$", "arn:obio:s3:::b/k$", true),
            ("arn:obio:s3:::b/a.c", "arn:obio:s3:::b/abc", false),
            ("ключ/*", "ключ/объект", true),
            ("ключ/?", "ключ/ж", true),
        ] {
            assert_eq!(wildcard_match(p, v), want, "{p:?} vs {v:?}");
        }
    }

    #[test]
    fn test_policy_parsing() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:obio:s3:::mybucket/*"]
                }
            ]
        }"#;

        let policy = BucketPolicy::from_json(json).unwrap();
        assert_eq!(policy.statements.len(), 1);
        assert_eq!(policy.statements[0].effect, Effect::Allow);
    }

    #[test]
    fn test_policy_evaluation_allow() {
        let mut policy = BucketPolicy::new();
        policy.add_statement(
            PolicyStatement::allow()
                .principal_any()
                .action("s3:GetObject")
                .resource("arn:obio:s3:::mybucket/*")
                .build(),
        );

        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/testuser",
            "s3:GetObject",
            "arn:obio:s3:::mybucket/mykey",
        );

        let evaluator = PolicyEvaluator::new();
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_evaluation_deny_takes_precedence() {
        let mut policy = BucketPolicy::new();
        policy.add_statement(
            PolicyStatement::allow()
                .principal_any()
                .action("s3:*")
                .resource("arn:obio:s3:::mybucket/*")
                .build(),
        );
        policy.add_statement(
            PolicyStatement::deny()
                .principal_any()
                .action("s3:DeleteObject")
                .resource("arn:obio:s3:::mybucket/*")
                .build(),
        );

        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/testuser",
            "s3:DeleteObject",
            "arn:obio:s3:::mybucket/mykey",
        );

        let evaluator = PolicyEvaluator::new();
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Deny);
    }

    #[test]
    fn test_policy_evaluation_implicit_deny() {
        let policy = BucketPolicy::new(); // Empty policy

        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/testuser",
            "s3:GetObject",
            "arn:obio:s3:::mybucket/mykey",
        );

        let evaluator = PolicyEvaluator::new();
        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_wildcard_matching() {
        let evaluator = PolicyEvaluator::new();

        assert!(evaluator.matches_pattern("arn:obio:s3:::bucket/*", "arn:obio:s3:::bucket/key"));
        assert!(
            evaluator.matches_pattern("arn:obio:s3:::bucket/*", "arn:obio:s3:::bucket/prefix/key")
        );
        assert!(!evaluator.matches_pattern("arn:obio:s3:::bucket/*", "arn:obio:s3:::other/key"));
        assert!(evaluator.matches_pattern("s3:*", "s3:GetObject"));
        assert!(evaluator.matches_pattern("*", "anything"));
    }

    #[test]
    fn test_builder() {
        let statement = PolicyStatement::allow()
            .sid("TestStatement")
            .principal_obio(vec!["arn:obio:iam::objectio:user/admin".to_string()])
            .actions(vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()])
            .resource("arn:obio:s3:::mybucket/*")
            .build();

        assert_eq!(statement.sid, Some("TestStatement".to_string()));
        assert_eq!(statement.effect, Effect::Allow);
        assert_eq!(statement.action.0.len(), 2);
    }

    #[test]
    fn test_date_greater_than_condition() {
        let evaluator = PolicyEvaluator::new();

        // Policy: Allow only after 2020-01-01
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["iceberg:*"],
                "Resource": ["*"],
                "Condition": {
                    "DateGreaterThan": {
                        "obio:CurrentTime": "2020-01-01T00:00:00+00:00"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        );

        // Current time is after 2020, so this should match
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Allow);
    }

    #[test]
    fn test_date_less_than_condition() {
        let evaluator = PolicyEvaluator::new();

        // Policy: Allow only before 2020-01-01 (this will be expired)
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["iceberg:*"],
                "Resource": ["*"],
                "Condition": {
                    "DateLessThan": {
                        "obio:CurrentTime": "2020-01-01T00:00:00+00:00"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        );

        // Current time is after 2020, so DateLessThan won't match -> implicit deny
        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_date_range_condition() {
        let evaluator = PolicyEvaluator::new();

        // Policy: Allow between 2020-01-01 and 2030-01-01
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["iceberg:*"],
                "Resource": ["*"],
                "Condition": {
                    "DateGreaterThan": {
                        "obio:CurrentTime": "2020-01-01T00:00:00+00:00"
                    },
                    "DateLessThan": {
                        "obio:CurrentTime": "2030-01-01T00:00:00+00:00"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        );

        // Current time should be between 2020 and 2030
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Allow);
    }

    #[test]
    fn test_principal_group_string_equals() {
        let evaluator = PolicyEvaluator::new();

        // Policy: Allow only members of data-engineers group
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["iceberg:*"],
                "Resource": ["*"],
                "Condition": {
                    "StringEquals": {
                        "obio:PrincipalGroup": "arn:obio:iam::objectio:group/data-engineers"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // User in the data-engineers group — should match
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        )
        .with_multi_variable(
            "obio:PrincipalGroup",
            vec![
                "arn:obio:iam::objectio:group/data-engineers".to_string(),
                "arn:obio:iam::objectio:group/analysts".to_string(),
            ],
        );
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Allow);

        // User NOT in the data-engineers group — should not match
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/bob",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        )
        .with_multi_variable(
            "obio:PrincipalGroup",
            vec!["arn:obio:iam::objectio:group/marketing".to_string()],
        );
        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );

        // User with no groups — should not match
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/carol",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        );
        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_principal_group_string_like() {
        let evaluator = PolicyEvaluator::new();

        // Policy: Deny users in any group matching "data-*"
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["iceberg:DropTable"],
                "Resource": ["*"],
                "Condition": {
                    "StringLike": {
                        "obio:PrincipalGroup": "arn:obio:iam::objectio:group/data-*"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // User in data-engineers group — should match the deny
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:DropTable",
            "arn:obio:iceberg:::db1/events",
        )
        .with_multi_variable(
            "obio:PrincipalGroup",
            vec!["arn:obio:iam::objectio:group/data-engineers".to_string()],
        );
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Deny);

        // User in marketing group — should not match the deny
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/bob",
            "iceberg:DropTable",
            "arn:obio:iceberg:::db1/events",
        )
        .with_multi_variable(
            "obio:PrincipalGroup",
            vec!["arn:obio:iam::objectio:group/marketing".to_string()],
        );
        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_principal_group_string_not_equals() {
        let evaluator = PolicyEvaluator::new();

        // Policy: Allow only if user is NOT in the interns group
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["iceberg:*"],
                "Resource": ["*"],
                "Condition": {
                    "StringNotEquals": {
                        "obio:PrincipalGroup": "arn:obio:iam::objectio:group/interns"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // User in interns group — StringNotEquals fails, no allow
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/intern1",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        )
        .with_multi_variable(
            "obio:PrincipalGroup",
            vec!["arn:obio:iam::objectio:group/interns".to_string()],
        );
        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );

        // User NOT in interns group — StringNotEquals passes, allow
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        )
        .with_multi_variable(
            "obio:PrincipalGroup",
            vec!["arn:obio:iam::objectio:group/engineers".to_string()],
        );
        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Allow);
    }

    #[test]
    fn test_custom_variable_conditions() {
        let evaluator = PolicyEvaluator::new();

        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["iceberg:*"],
                "Resource": ["*"],
                "Condition": {
                    "StringEquals": {
                        "iceberg:namespace": "production"
                    }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // With production namespace variable — should deny
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::production/events",
        )
        .with_variable("iceberg:namespace", "production");

        assert_eq!(evaluator.evaluate(&policy, &context), PolicyDecision::Deny);

        // With staging namespace variable — should not match the deny
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::staging/events",
        )
        .with_variable("iceberg:namespace", "staging");

        assert_eq!(
            evaluator.evaluate(&policy, &context),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_evaluate_with_explanation_deny() {
        let evaluator = PolicyEvaluator::new();
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyDrops",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["iceberg:DropTable"],
                "Resource": ["arn:obio:iceberg:::*"]
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:DropTable",
            "arn:obio:iceberg:::db1/events",
        );

        let result = evaluator.evaluate_with_explanation(&policy, &context, "namespace:db1");
        assert_eq!(result.decision, PolicyDecision::Deny);
        let ms = result.matched_statement.unwrap();
        assert_eq!(ms.sid, Some("DenyDrops".to_string()));
        assert_eq!(ms.effect, Effect::Deny);
        assert_eq!(ms.source, "namespace:db1");
    }

    #[test]
    fn test_evaluate_with_explanation_allow() {
        let evaluator = PolicyEvaluator::new();
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowReads",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["iceberg:LoadTable"],
                "Resource": ["*"]
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        );

        let result = evaluator.evaluate_with_explanation(&policy, &context, "catalog");
        assert_eq!(result.decision, PolicyDecision::Allow);
        let ms = result.matched_statement.unwrap();
        assert_eq!(ms.sid, Some("AllowReads".to_string()));
        assert_eq!(ms.effect, Effect::Allow);
        assert_eq!(ms.source, "catalog");
    }

    #[test]
    fn test_evaluate_with_explanation_implicit_deny() {
        let evaluator = PolicyEvaluator::new();
        let policy = BucketPolicy::new(); // Empty policy
        let context = RequestContext::new(
            "arn:obio:iam::objectio:user/alice",
            "iceberg:LoadTable",
            "arn:obio:iceberg:::db1/events",
        );

        let result = evaluator.evaluate_with_explanation(&policy, &context, "catalog");
        assert_eq!(result.decision, PolicyDecision::ImplicitDeny);
        assert!(result.matched_statement.is_none());
    }

    #[test]
    fn test_cidr_ipv4_matching() {
        let evaluator = PolicyEvaluator::new();

        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": ["*"],
                "Condition": {
                    "IpAddress": { "aws:SourceIp": "10.0.0.0/8" }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // IP inside 10.0.0.0/8
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("10.1.2.3".parse().unwrap());
        assert_eq!(evaluator.evaluate(&policy, &ctx), PolicyDecision::Allow);

        // IP outside 10.0.0.0/8
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("192.168.1.1".parse().unwrap());
        assert_eq!(
            evaluator.evaluate(&policy, &ctx),
            PolicyDecision::ImplicitDeny
        );

        // Exact boundary: 10.255.255.255 is in /8
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("10.255.255.255".parse().unwrap());
        assert_eq!(evaluator.evaluate(&policy, &ctx), PolicyDecision::Allow);

        // 11.0.0.0 is NOT in 10.0.0.0/8
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("11.0.0.0".parse().unwrap());
        assert_eq!(
            evaluator.evaluate(&policy, &ctx),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_cidr_ipv4_slash24() {
        let evaluator = PolicyEvaluator::new();

        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": ["*"],
                "Condition": {
                    "NotIpAddress": { "aws:SourceIp": "192.168.1.0/24" }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // IP inside 192.168.1.0/24 — NotIpAddress does NOT match → no deny
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("192.168.1.50".parse().unwrap());
        assert_eq!(
            evaluator.evaluate(&policy, &ctx),
            PolicyDecision::ImplicitDeny
        );

        // IP outside 192.168.1.0/24 — NotIpAddress matches → deny
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("192.168.2.1".parse().unwrap());
        assert_eq!(evaluator.evaluate(&policy, &ctx), PolicyDecision::Deny);
    }

    #[test]
    fn test_cidr_ipv6_matching() {
        let evaluator = PolicyEvaluator::new();

        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": ["*"],
                "Condition": {
                    "IpAddress": { "aws:SourceIp": "fd00::/8" }
                }
            }]
        }"#;
        let policy = BucketPolicy::from_json(json).unwrap();

        // fd12::1 is in fd00::/8
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("fd12::1".parse().unwrap());
        assert_eq!(evaluator.evaluate(&policy, &ctx), PolicyDecision::Allow);

        // fe80::1 is NOT in fd00::/8
        let ctx = RequestContext::new(
            "arn:obio:iam::objectio:user/a",
            "s3:GetObject",
            "arn:aws:s3:::b/*",
        )
        .with_source_ip("fe80::1".parse().unwrap());
        assert_eq!(
            evaluator.evaluate(&policy, &ctx),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn test_cidr_wildcard_ranges() {
        let evaluator = PolicyEvaluator::new();
        // 0.0.0.0/0 matches any IPv4
        assert!(evaluator.ip_matches_cidr(&"1.2.3.4".parse().unwrap(), "0.0.0.0/0"));
        // ::/0 matches any IPv6
        assert!(evaluator.ip_matches_cidr(&"::1".parse().unwrap(), "::/0"));
        // Exact IP match (no prefix)
        assert!(evaluator.ip_matches_cidr(&"10.0.0.1".parse().unwrap(), "10.0.0.1"));
        assert!(!evaluator.ip_matches_cidr(&"10.0.0.2".parse().unwrap(), "10.0.0.1"));
    }
}

#[cfg(test)]
mod principal_spelling_tests {
    use super::*;

    /// `AWS` is what every S3 tool and tutorial emits. Rejecting it made the
    /// whole policy fail to parse, and an unparseable policy is treated as no
    /// policy — so the grant silently did nothing.
    #[test]
    fn aws_principal_is_accepted() {
        let json = r#"{"Version":"2012-10-17","Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":["arn:objectio:iam::user/bot"]},
            "Action":["s3:GetObject"],
            "Resource":["arn:obio:s3:::b/*"]}]}"#;
        let p = BucketPolicy::from_json(json).expect("AWS principal must parse");
        match &p.statements[0].principal {
            Principal::OBIO(v) => assert_eq!(v, &["arn:objectio:iam::user/bot"]),
            other => panic!("expected specific principals, got {other:?}"),
        }
    }

    #[test]
    fn obio_spelling_still_works() {
        let json = r#"{"Version":"2012-10-17","Statement":[{
            "Effect":"Allow",
            "Principal":{"OBIO":["arn:objectio:iam::user/bot"]},
            "Action":["s3:GetObject"],
            "Resource":["arn:obio:s3:::b/*"]}]}"#;
        assert!(BucketPolicy::from_json(json).is_ok());
    }

    #[test]
    fn an_aws_principal_actually_grants() {
        let json = r#"{"Version":"2012-10-17","Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":["arn:objectio:iam::user/bot"]},
            "Action":["s3:GetObject"],
            "Resource":["arn:obio:s3:::b/*"]}]}"#;
        let policy = BucketPolicy::from_json(json).unwrap();
        let ctx = RequestContext::new(
            "arn:objectio:iam::user/bot",
            "s3:GetObject",
            "arn:obio:s3:::b/k",
        );
        assert_eq!(
            PolicyEvaluator::new().evaluate(&policy, &ctx),
            PolicyDecision::Allow
        );
        // A different user is not covered by it.
        let other = RequestContext::new(
            "arn:objectio:iam::user/someone-else",
            "s3:GetObject",
            "arn:obio:s3:::b/k",
        );
        assert_eq!(
            PolicyEvaluator::new().evaluate(&policy, &other),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn a_principal_with_no_recognised_key_is_still_an_error() {
        let json = r#"{"Version":"2012-10-17","Statement":[{
            "Effect":"Allow","Principal":{"Nonsense":["x"]},
            "Action":["s3:GetObject"],"Resource":["arn:obio:s3:::b/*"]}]}"#;
        assert!(BucketPolicy::from_json(json).is_err());
    }

    /// A policy written for S3, with `arn:aws:` resources, grants what it says.
    #[test]
    fn aws_partition_arns_name_the_same_resources() {
        let policy: BucketPolicy = serde_json::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
                "Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}"#,
        )
        .unwrap();
        let evaluator = PolicyEvaluator::new();
        assert!(
            evaluator.matches_resource(&policy.statements[0].resource, "arn:obio:s3:::mybucket/k")
        );
        assert!(
            !evaluator.matches_resource(&policy.statements[0].resource, "arn:obio:s3:::other/k")
        );
    }

    fn allows(policy: &str, context: &RequestContext) -> PolicyDecision {
        PolicyEvaluator::new().evaluate(&BucketPolicy::from_json(policy).unwrap(), context)
    }

    fn get_request(vars: &[(&str, &str)]) -> RequestContext {
        let mut c = RequestContext::new(
            "arn:obio:iam::objectio:user/u",
            "s3:GetObject",
            "arn:obio:s3:::b/k",
        );
        for (k, v) in vars {
            c = c.with_variable(*k, *v);
        }
        c
    }

    fn policy_with(effect: &str, condition: &str) -> String {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"{effect}","Principal":"*",
                "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{condition}}}]}}"#
        )
    }

    /// An operator not understood is refused, not dropped: dropping it made
    /// an Allow it guarded unconditional.
    #[test]
    fn a_policy_with_an_unknown_operator_is_refused() {
        let p = policy_with("Allow", r#"{"StringLooksLike":{"s3:prefix":"a"}}"#);
        assert!(BucketPolicy::from_json(&p).is_err());
    }

    #[test]
    fn bool_and_numeric_conditions_hold_only_when_true() {
        let p = policy_with("Allow", r#"{"Bool":{"aws:SecureTransport":true}}"#);
        assert_eq!(
            allows(&p, &get_request(&[("aws:SecureTransport", "true")])),
            PolicyDecision::Allow
        );
        assert_eq!(
            allows(&p, &get_request(&[("aws:SecureTransport", "false")])),
            PolicyDecision::ImplicitDeny
        );
        assert_eq!(allows(&p, &get_request(&[])), PolicyDecision::ImplicitDeny);
        let p = policy_with("Allow", r#"{"NumericLessThanEquals":{"s3:max-keys":"10"}}"#);
        assert_eq!(
            allows(&p, &get_request(&[("s3:max-keys", "10")])),
            PolicyDecision::Allow
        );
        assert_eq!(
            allows(&p, &get_request(&[("s3:max-keys", "11")])),
            PolicyDecision::ImplicitDeny
        );
    }

    /// A missing key: positive operators don't hold, negated ones and
    /// IfExists do, and Null tests for exactly that.
    #[test]
    fn a_missing_key_is_handled_as_iam_does() {
        let deny_unencrypted = policy_with(
            "Deny",
            r#"{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}}"#,
        );
        assert_eq!(
            allows(&deny_unencrypted, &get_request(&[])),
            PolicyDecision::Deny
        );
        assert_eq!(
            allows(
                &deny_unencrypted,
                &get_request(&[("s3:x-amz-server-side-encryption", "AES256")])
            ),
            PolicyDecision::ImplicitDeny
        );
        let if_exists = policy_with(
            "Allow",
            r#"{"StringEqualsIfExists":{"s3:x-amz-acl":"private"}}"#,
        );
        assert_eq!(allows(&if_exists, &get_request(&[])), PolicyDecision::Allow);
        assert_eq!(
            allows(&if_exists, &get_request(&[("s3:x-amz-acl", "public-read")])),
            PolicyDecision::ImplicitDeny
        );
        let null = policy_with(
            "Deny",
            r#"{"Null":{"s3:x-amz-server-side-encryption":"true"}}"#,
        );
        assert_eq!(allows(&null, &get_request(&[])), PolicyDecision::Deny);
    }

    /// NotPrincipal only on a Deny, and then it spares exactly those named.
    #[test]
    fn not_principal_spares_whom_it_names_and_only_denies() {
        let allow = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "NotPrincipal":{"AWS":"arn:obio:iam::objectio:user/x"},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}"#;
        assert!(BucketPolicy::from_json(allow).is_err());
        let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
            "NotPrincipal":{"AWS":"arn:obio:iam::objectio:user/admin"},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}"#;
        let evaluate = |user: &str| {
            PolicyEvaluator::new().evaluate(
                &BucketPolicy::from_json(deny).unwrap(),
                &RequestContext::new(user, "s3:GetObject", "arn:obio:s3:::b/k"),
            )
        };
        assert_eq!(
            evaluate("arn:obio:iam::objectio:user/admin"),
            PolicyDecision::ImplicitDeny
        );
        assert_eq!(
            evaluate("arn:obio:iam::objectio:user/eve"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn a_trust_policy_needs_no_resource() {
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Principal":{"Federated":"idp.example.com"},
            "Action":"sts:AssumeRoleWithWebIdentity"}]}"#;
        assert!(BucketPolicy::from_json(doc).is_err());
        let trust = BucketPolicy::from_trust_json(doc).unwrap();
        let ctx = RequestContext::new(
            "Federated:idp.example.com",
            "sts:AssumeRoleWithWebIdentity",
            "arn:obio:iam::acme:role/ci",
        );
        assert_eq!(
            PolicyEvaluator::new().evaluate(&trust, &ctx),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn a_policy_is_public_when_it_allows_everyone_unpinned() {
        let p = |doc: &str| BucketPolicy::from_json(doc).unwrap();
        let st = |principal: &str, cond: &str| {
            format!(
                r#"{{"Statement":[{{"Effect":"Allow","Principal":{principal},
                "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"{cond}}}]}}"#
            )
        };
        assert!(p(&st(r#""*""#, "")).is_public());
        assert!(p(&st(r#"{"AWS":"*"}"#, "")).is_public());
        assert!(p(&st(r#"{"AWS":["*"]}"#, "")).is_public());
        assert!(!p(&st(r#"{"AWS":"arn:aws:iam::acme:user/u"}"#, "")).is_public());
        // Pinned to a network or a source: not public.
        let ip = r#","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#;
        assert!(!p(&st(r#""*""#, ip)).is_public());
        // ... unless the network is the internet, or the match is negative.
        let any = r#","Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}"#;
        assert!(p(&st(r#""*""#, any)).is_public());
        let not = r#","Condition":{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#;
        assert!(p(&st(r#""*""#, not)).is_public());
        // A condition on something else doesn't pin the caller.
        let tls = r#","Condition":{"Bool":{"aws:SecureTransport":"true"}}"#;
        assert!(p(&st(r#""*""#, tls)).is_public());
        // A Deny for everyone isn't public.
        let deny = r#"{"Statement":[{"Effect":"Deny","Principal":"*",
            "Action":"s3:*","Resource":"arn:aws:s3:::b/*"}]}"#;
        assert!(!p(deny).is_public());
    }

    #[test]
    fn an_anonymous_caller_gets_only_grants_to_everyone() {
        let doc = r#"{"Statement":[
            {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::acme:user/u"},
             "Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"},
            {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
            {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/secret"}]}"#;
        let anon = BucketPolicy::from_json(doc).unwrap().for_anonymous();
        assert_eq!(anon.statements.len(), 2);
        let eval = |action: &str, res: &str| {
            PolicyEvaluator::new().evaluate(&anon, &RequestContext::new("anonymous", action, res))
        };
        assert_eq!(
            eval("s3:GetObject", "arn:obio:s3:::b/k"),
            PolicyDecision::Allow
        );
        assert_eq!(
            eval("s3:GetObject", "arn:obio:s3:::b/secret"),
            PolicyDecision::Deny
        );
        assert_eq!(
            eval("s3:PutObject", "arn:obio:s3:::b/k"),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn a_prefix_condition_sees_the_listings_prefix() {
        let p = BucketPolicy::from_json(
            r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket",
            "Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":"home/u/*"}}}]}"#,
        )
        .unwrap();
        let list = |prefix: &str| {
            PolicyEvaluator::new().evaluate(
                &p,
                &RequestContext::new("u", "s3:ListBucket", "arn:obio:s3:::b")
                    .with_variable("s3:prefix", prefix),
            )
        };
        assert_eq!(list("home/u/docs"), PolicyDecision::Allow);
        assert_eq!(list("home/other/"), PolicyDecision::ImplicitDeny);
    }

    #[test]
    fn source_conditions_see_the_address_and_endpoint() {
        let p = BucketPolicy::from_json(
            r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
            "Resource":"arn:aws:s3:::b/*","Condition":{
              "IpAddress":{"aws:SourceIp":"10.0.0.0/8"},
              "StringEquals":{"aws:SourceVpce":"internal"}}}]}"#,
        )
        .unwrap();
        assert!(!p.is_public());
        let get = |ip: &str, endpoint: Option<&str>| {
            let mut ctx = RequestContext::new("anonymous", "s3:GetObject", "arn:obio:s3:::b/k")
                .with_source_ip(ip.parse().unwrap());
            if let Some(e) = endpoint {
                ctx = ctx.with_variable("aws:SourceVpce", e);
            }
            PolicyEvaluator::new().evaluate(&p, &ctx)
        };
        assert_eq!(get("10.1.2.3", Some("internal")), PolicyDecision::Allow);
        assert_eq!(get("10.1.2.3", None), PolicyDecision::ImplicitDeny);
        assert_eq!(
            get("10.1.2.3", Some("external")),
            PolicyDecision::ImplicitDeny
        );
        assert_eq!(
            get("203.0.113.1", Some("internal")),
            PolicyDecision::ImplicitDeny
        );
    }
}

#[cfg(test)]
mod arn_spelling_tests {
    use super::*;

    #[test]
    fn every_spelling_of_an_arn_is_one_arn() {
        for (spelled, canonical) in [
            ("arn:aws:s3:::bucket/key", "arn:obio:s3:::bucket/key"),
            ("arn:obio:s3:::bucket", "arn:obio:s3:::bucket"),
            (
                "arn:objectio:iam::acme:user/app",
                "arn:obio:iam::acme:user/app",
            ),
            (
                "arn:objectio:iam::user/admin",
                "arn:obio:iam::objectio:user/admin",
            ),
            ("arn:aws:iam:::role/ops", "arn:obio:iam::objectio:role/ops"),
            (
                "arn:aws:iam::acme:user/team/alice",
                "arn:obio:iam::acme:user/team/alice",
            ),
            (
                "arn:aws:sts:::assumed-role/ops/s",
                "arn:obio:sts::objectio:assumed-role/ops/s",
            ),
            ("*", "*"),
        ] {
            assert_eq!(canonical_arn(spelled), canonical, "{spelled}");
        }
    }

    fn decide(policy: &str, user: &str, action: &str, resource: &str) -> PolicyDecision {
        let policy = BucketPolicy::from_json(policy).unwrap();
        PolicyEvaluator::new().evaluate(&policy, &RequestContext::new(user, action, resource))
    }

    #[test]
    fn a_user_named_in_any_spelling_is_the_user() {
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::acme:user/app"},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}"#;
        let resource = "arn:obio:s3:::b/k";
        assert_eq!(
            decide(
                policy,
                "arn:objectio:iam::acme:user/app",
                "s3:GetObject",
                resource
            ),
            PolicyDecision::Allow
        );
        assert_eq!(
            decide(
                policy,
                "arn:objectio:iam::other:user/app",
                "s3:GetObject",
                resource
            ),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn a_service_wildcard_grants_only_that_service() {
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Action":"s3:*","Resource":"*"}]}"#;
        let user = "arn:objectio:iam::acme:user/app";
        assert_eq!(
            decide(policy, user, "s3:PutObject", "*"),
            PolicyDecision::Allow
        );
        assert_eq!(
            decide(policy, user, "iam:CreateUser", "*"),
            PolicyDecision::ImplicitDeny
        );
    }

    #[test]
    fn a_single_statement_needs_no_list() {
        let policy = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow",
            "Action":"s3:GetObject","Resource":"*"}}"#;
        assert_eq!(
            decide(policy, "arn:obio:iam::a:user/u", "s3:GetObject", "*"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn action_names_are_case_insensitive() {
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Action":"iam:get*","Resource":"*"}]}"#;
        assert_eq!(
            decide(policy, "arn:obio:iam::a:user/u", "iam:GetUser", "*"),
            PolicyDecision::Allow
        );
    }
}
