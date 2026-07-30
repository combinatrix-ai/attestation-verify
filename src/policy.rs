//! GitHub identity policy types (DESIGN.md "Identity policy").
//!
//! This module defines *what identity to require*: source repository,
//! signer workflow, and revision. It intentionally contains no matching
//! logic — comparing a policy against a certificate's authenticated claims
//! is verification work, not parsing work, and belongs to a later task.
//! Every constructor here validates its own inputs, so any `GithubPolicy`
//! you can hold is already well-formed.

use crate::error::{Error, PolicyError};
use crate::parse_util;

fn policy_error(reason: String) -> Error {
    Error::Policy(PolicyError::InvalidConfiguration(reason))
}

/// A GitHub identity policy: the source repository/ref/commit an artifact
/// must come from, and the workflow that must have signed it.
///
/// Constructed via [`GithubPolicy::builder`]. The OIDC issuer is pinned
/// internally to `https://token.actions.githubusercontent.com` and is not
/// configurable.
#[derive(Debug, Clone)]
pub struct GithubPolicy {
    /// Where the code came from.
    pub source: SourcePolicy,
    /// Which workflow signed it.
    pub signer: SignerPolicy,
}

impl GithubPolicy {
    /// Starts building a [`GithubPolicy`].
    #[must_use]
    pub fn builder() -> GithubPolicyBuilder {
        GithubPolicyBuilder::default()
    }
}

/// Builder for [`GithubPolicy`]. Validation happens once, in
/// [`GithubPolicyBuilder::build`]; a successfully-built `GithubPolicy` is
/// guaranteed well-formed from then on (DESIGN.md "Core decisions" item
/// 5: policy is validated once at build time and reused).
#[derive(Debug, Clone, Default)]
pub struct GithubPolicyBuilder {
    source: Option<SourcePolicy>,
    signer: Option<SignerPolicy>,
}

impl GithubPolicyBuilder {
    /// Sets the source policy (where the code came from).
    #[must_use]
    pub fn source(mut self, source: SourcePolicy) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets the signer policy (which workflow signed it).
    #[must_use]
    pub fn signer(mut self, signer: SignerPolicy) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Builds the policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if either
    /// [`GithubPolicyBuilder::source`] or [`GithubPolicyBuilder::signer`]
    /// was never called.
    pub fn build(self) -> Result<GithubPolicy, Error> {
        let source = self
            .source
            .ok_or_else(|| policy_error("source policy is required".to_owned()))?;
        let signer = self
            .signer
            .ok_or_else(|| policy_error("signer policy is required".to_owned()))?;
        Ok(GithubPolicy { source, signer })
    }
}

/// Where the code must come from: a repository, a ref policy, and
/// optionally an exact commit.
#[derive(Debug, Clone)]
pub struct SourcePolicy {
    /// The required source repository.
    pub repository: RepositoryIdentity,
    /// The required git ref.
    pub git_ref: RefPolicy,
    /// An optional exact commit requirement, independent of `git_ref`.
    pub commit: Option<CommitSha>,
}

/// Which workflow must have signed: a repository, a workflow file path,
/// and a revision policy.
///
/// Kept separate from [`SourcePolicy`] because reusable workflows make
/// "repository + workflow path" alone ambiguous: the workflow file can
/// live in a different repository than the code it signed for.
#[derive(Debug, Clone)]
pub struct SignerPolicy {
    /// The repository the signing workflow lives in.
    pub repository: RepositoryIdentity,
    /// The workflow file path within that repository.
    pub path: WorkflowPath,
    /// The required revision of the workflow file itself.
    pub revision: WorkflowRevisionPolicy,
}

/// A GitHub repository identity: owner/name, optionally pinned to numeric
/// IDs.
///
/// Numeric owner id protects against owner rename/recreation; numeric
/// repository id protects against repository rename, transfer, or
/// recreation. Fields are private and validated at construction: an
/// empty owner or name is rejected, so any `RepositoryIdentity` you can
/// hold is well-formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryIdentity {
    owner: String,
    name: String,
    owner_id: Option<u64>,
    repository_id: Option<u64>,
}

impl RepositoryIdentity {
    /// Builds a [`RepositoryIdentity`] from separate owner and name
    /// strings.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if `owner` or `name`
    /// is empty.
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Result<Self, Error> {
        let owner = owner.into();
        let name = name.into();
        if owner.is_empty() {
            return Err(policy_error(
                "repository owner must not be empty".to_owned(),
            ));
        }
        if name.is_empty() {
            return Err(policy_error("repository name must not be empty".to_owned()));
        }
        Ok(RepositoryIdentity {
            owner,
            name,
            owner_id: None,
            repository_id: None,
        })
    }

    /// Builds a [`RepositoryIdentity`] by splitting `"owner/name"`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if `owner_slash_name`
    /// does not contain exactly one `/`, or either side is empty.
    pub fn parse(owner_slash_name: &str) -> Result<Self, Error> {
        let Some((owner, name)) = owner_slash_name.split_once('/') else {
            return Err(policy_error(format!(
                "expected \"owner/name\", got {owner_slash_name:?}"
            )));
        };
        if name.contains('/') {
            return Err(policy_error(format!(
                "expected exactly one '/' in \"owner/name\", got {owner_slash_name:?}"
            )));
        }
        Self::new(owner, name)
    }

    /// Pins the numeric owner id (protects against owner
    /// rename/recreation).
    #[must_use]
    pub fn with_owner_id(mut self, owner_id: u64) -> Self {
        self.owner_id = Some(owner_id);
        self
    }

    /// Pins the numeric repository id (protects against repository
    /// rename/transfer/recreation).
    #[must_use]
    pub fn with_repository_id(mut self, repository_id: u64) -> Self {
        self.repository_id = Some(repository_id);
        self
    }

    /// The repository owner (user or organization login).
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The repository name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pinned numeric owner id, if set.
    #[must_use]
    pub fn owner_id(&self) -> Option<u64> {
        self.owner_id
    }

    /// The pinned numeric repository id, if set.
    #[must_use]
    pub fn repository_id(&self) -> Option<u64> {
        self.repository_id
    }
}

/// How a git ref must be matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefPolicy {
    /// The ref must match exactly, e.g. `"refs/tags/v0.4.0"`.
    Exact(String),
    /// The ref must match a glob pattern. Documented as the weaker form:
    /// prefer [`RefPolicy::Exact`] for release/updater callers.
    Glob(String),
}

/// A workflow file path, e.g. `".github/workflows/release.yml"`.
///
/// Private inner field, validated non-empty at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowPath(String);

impl WorkflowPath {
    /// Builds a [`WorkflowPath`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if `path` is empty.
    pub fn new(path: impl Into<String>) -> Result<Self, Error> {
        let path = path.into();
        if path.is_empty() {
            return Err(policy_error("workflow path must not be empty".to_owned()));
        }
        Ok(WorkflowPath(path))
    }

    /// The workflow path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A git commit SHA-1, as 20 raw bytes.
///
/// Private inner field, validated as exactly 40 hex characters at
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitSha([u8; 20]);

impl CommitSha {
    /// Parses a 40-hex-character commit SHA.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if `sha` is not
    /// exactly 40 hexadecimal characters.
    pub fn new(sha: &str) -> Result<Self, Error> {
        let bytes: [u8; 20] = parse_util::strict_hex("commit_sha", sha)
            .map_err(|e| policy_error(format!("invalid commit sha: {e}")))?;
        Ok(CommitSha(bytes))
    }

    /// The commit SHA as canonical lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// How the signing workflow file's own revision must be matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowRevisionPolicy {
    /// Any revision of the workflow file is accepted.
    Any,
    /// The workflow file must be at a specific ref.
    Ref(String),
    /// The workflow file must be at a specific commit.
    Sha(CommitSha),
}

#[cfg(test)]
mod tests {
    use super::{GithubPolicy, RepositoryIdentity, SignerPolicy, SourcePolicy, WorkflowPath};
    use super::{RefPolicy, WorkflowRevisionPolicy};
    use crate::error::{Error, PolicyError};

    #[test]
    fn repository_identity_parses_owner_slash_name() -> Result<(), Box<dyn std::error::Error>> {
        let repo = RepositoryIdentity::parse("combinatrix-ai/dlgt")?;
        if repo.owner() != "combinatrix-ai" || repo.name() != "dlgt" {
            return Err("owner/name split mismatch".into());
        }
        Ok(())
    }

    #[test]
    fn repository_identity_with_ids_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let repo = RepositoryIdentity::new("combinatrix-ai", "dlgt")?
            .with_owner_id(1)
            .with_repository_id(2);
        if repo.owner_id() != Some(1) || repo.repository_id() != Some(2) {
            return Err("numeric id round trip mismatch".into());
        }
        Ok(())
    }

    #[test]
    fn repository_identity_rejects_empty_owner() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(RepositoryIdentity::new("", "dlgt"))
    }

    #[test]
    fn repository_identity_rejects_empty_name() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(RepositoryIdentity::new("combinatrix-ai", ""))
    }

    #[test]
    fn repository_identity_parse_rejects_missing_slash() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(RepositoryIdentity::parse("no-slash-here"))
    }

    #[test]
    fn repository_identity_parse_rejects_extra_slash() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(RepositoryIdentity::parse("owner/name/extra"))
    }

    #[test]
    fn repository_identity_parse_rejects_empty_owner() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(RepositoryIdentity::parse("/name"))
    }

    #[test]
    fn workflow_path_rejects_empty() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(WorkflowPath::new(""))
    }

    #[test]
    fn commit_sha_rejects_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(super::CommitSha::new(&"a".repeat(39)))
    }

    #[test]
    fn commit_sha_round_trips_hex() -> Result<(), Box<dyn std::error::Error>> {
        let sha_hex = "a".repeat(40);
        let sha = super::CommitSha::new(&sha_hex)?;
        if sha.to_hex() != sha_hex {
            return Err("commit sha hex round trip mismatch".into());
        }
        Ok(())
    }

    #[test]
    fn github_policy_builder_requires_both_halves() -> Result<(), Box<dyn std::error::Error>> {
        expect_policy_error(GithubPolicy::builder().build())
    }

    #[test]
    fn github_policy_builder_builds_with_both_halves() -> Result<(), Box<dyn std::error::Error>> {
        let source = SourcePolicy {
            repository: RepositoryIdentity::parse("combinatrix-ai/dlgt")?
                .with_owner_id(1)
                .with_repository_id(2),
            git_ref: RefPolicy::Exact("refs/tags/v0.4.0".to_owned()),
            commit: None,
        };
        let signer = SignerPolicy {
            repository: RepositoryIdentity::parse("combinatrix-ai/dlgt")?,
            path: WorkflowPath::new(".github/workflows/release.yml")?,
            revision: WorkflowRevisionPolicy::Any,
        };
        GithubPolicy::builder()
            .source(source)
            .signer(signer)
            .build()?;
        Ok(())
    }

    fn expect_policy_error<T: std::fmt::Debug>(
        result: Result<T, Error>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match result {
            Err(Error::Policy(PolicyError::InvalidConfiguration(_))) => Ok(()),
            other => {
                Err(format!("expected PolicyError::InvalidConfiguration, got {other:?}").into())
            }
        }
    }
}
