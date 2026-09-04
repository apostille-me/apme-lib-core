//! Which managed Postgres hosts the isolated admin database.
//!
//! The admin plane started on AWS RDS, where the reviewed identity is simply
//! an exact hostname. Neon and Supabase are both legitimate homes for an admin
//! database, but each departs from that shape in a way the RDS-only check
//! rejects outright — or, worse, would wave through if the check were merely
//! loosened:
//!
//! * **Neon** puts the compute endpoint id in the hostname
//!   (`ep-cool-name-123456.us-east-2.aws.neon.tech`) and, for drivers that do
//!   not send SNI, repeats it in `options=endpoint%3Dep-...`. A mismatch
//!   between the two silently routes to a *different* compute endpoint, so
//!   when the option is present it must agree with the host.
//! * **Supabase** routes through Supavisor, whose username carries the project
//!   reference (`postgres.abcdefghijklmnopqrst`). That dot is illegal in the
//!   RDS role check, and the pooler answers on two ports with materially
//!   different semantics — 6543 is transaction pooling, where session state
//!   does not persist between statements.
//!
//! Each provider therefore gets its own rule rather than a widened common one.

use url::Url;

/// The managed Postgres provider hosting the admin database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminDatabaseProvider {
    /// AWS RDS or any host matched by exact name.
    Rds,
    /// Neon serverless Postgres.
    Neon,
    /// Supabase, direct or through the Supavisor pooler.
    Supabase,
}

impl AdminDatabaseProvider {
    /// Parses the configured provider name.
    ///
    /// Unknown values are rejected rather than defaulted: silently falling back
    /// to the strictest provider would still be the *wrong* provider, and
    /// falling back to the loosest would be a security regression.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rds" | "aws" | "aws-rds" => Some(Self::Rds),
            "neon" | "neondb" => Some(Self::Neon),
            "supabase" => Some(Self::Supabase),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rds => "rds",
            Self::Neon => "neon",
            Self::Supabase => "supabase",
        }
    }

    /// Domains the provider's admin endpoints must sit under.
    #[must_use]
    const fn required_suffixes(self) -> &'static [&'static str] {
        match self {
            Self::Rds => &[],
            Self::Neon => &[".neon.tech"],
            Self::Supabase => &[".supabase.co", ".supabase.com"],
        }
    }

    /// Is `role` a legal runtime role name for this provider?
    ///
    /// Supabase's pooler username is `postgres.<project-ref>`; exactly one dot
    /// is permitted, and neither side of it may be empty. Every other provider
    /// keeps the strict `[A-Za-z0-9_]` rule.
    #[must_use]
    pub fn valid_role(self, role: &str) -> bool {
        fn plain(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 63
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }

        match self {
            Self::Supabase => match role.split_once('.') {
                Some((user, project)) => plain(user) && plain(project),
                None => plain(role),
            },
            Self::Rds | Self::Neon => plain(role),
        }
    }

    /// Provider-specific checks beyond the shared identity rules.
    ///
    /// The caller has already established scheme, exact host, role, database
    /// and `sslmode=verify-full`; this adds only what is provider-shaped.
    pub fn validate_endpoint(self, url: &Url) -> Result<(), ProviderError> {
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();

        let suffixes = self.required_suffixes();
        if !suffixes.is_empty() && !suffixes.iter().any(|suffix| host.ends_with(suffix)) {
            return Err(ProviderError::HostNotProviderOwned);
        }

        match self {
            Self::Rds => Ok(()),
            Self::Neon => validate_neon(url, &host),
            Self::Supabase => validate_supabase(url, &host),
        }
    }
}

/// Neon: when `options=endpoint=<id>` is present it must name the same compute
/// endpoint as the hostname. Disagreement routes to another endpoint entirely.
fn validate_neon(url: &Url, host: &str) -> Result<(), ProviderError> {
    let host_endpoint = host.split('.').next().unwrap_or_default();
    if !host_endpoint.starts_with("ep-") {
        return Err(ProviderError::NeonEndpointMissing);
    }

    let options = url
        .query_pairs()
        .filter(|(name, _)| name == "options")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    if options.len() > 1 {
        return Err(ProviderError::NeonEndpointMismatch);
    }
    let Some(options) = options.first() else {
        return Ok(());
    };

    // `options` is a space-separated libpq option string; find `endpoint=...`.
    let declared = options
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("endpoint="))
        .collect::<Vec<_>>();
    match declared.as_slice() {
        [] => Ok(()),
        [only] if *only == host_endpoint => Ok(()),
        _ => Err(ProviderError::NeonEndpointMismatch),
    }
}

/// Supabase: the pooler answers on 5432 (session) and 6543 (transaction).
/// Transaction pooling does not carry session state between statements, which
/// the admin contexts rely on when they prove read-only versus writable, so it
/// is refused rather than left to fail confusingly at runtime.
fn validate_supabase(url: &Url, host: &str) -> Result<(), ProviderError> {
    let pooled = host.contains("pooler.supabase.com");
    match url.port() {
        Some(6543) => Err(ProviderError::SupabaseTransactionPooler),
        Some(5432) | None => Ok(()),
        Some(_) if pooled => Err(ProviderError::SupabaseUnexpectedPort),
        Some(_) => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderError {
    #[error("admin database host is not owned by the configured provider")]
    HostNotProviderOwned,
    #[error("neon admin endpoint id is missing from the hostname")]
    NeonEndpointMissing,
    #[error("neon endpoint option disagrees with the hostname")]
    NeonEndpointMismatch,
    #[error("supabase transaction pooler (6543) cannot carry admin session state")]
    SupabaseTransactionPooler,
    #[error("supabase pooler port is not a recognized endpoint")]
    SupabaseUnexpectedPort,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> Url {
        Url::parse(value).expect("test url parses")
    }

    #[test]
    fn provider_names_round_trip_and_reject_junk() {
        assert_eq!(
            AdminDatabaseProvider::parse("neon"),
            Some(AdminDatabaseProvider::Neon)
        );
        assert_eq!(
            AdminDatabaseProvider::parse("NeonDB"),
            Some(AdminDatabaseProvider::Neon)
        );
        assert_eq!(
            AdminDatabaseProvider::parse("supabase"),
            Some(AdminDatabaseProvider::Supabase)
        );
        assert_eq!(
            AdminDatabaseProvider::parse("rds"),
            Some(AdminDatabaseProvider::Rds)
        );
        assert_eq!(AdminDatabaseProvider::parse("planetscale"), None);
        assert_eq!(AdminDatabaseProvider::parse(""), None);
    }

    #[test]
    fn only_supabase_accepts_a_dotted_pooler_role() {
        let dotted = "postgres.abcdefghijklmnopqrst";
        assert!(AdminDatabaseProvider::Supabase.valid_role(dotted));
        assert!(!AdminDatabaseProvider::Neon.valid_role(dotted));
        assert!(!AdminDatabaseProvider::Rds.valid_role(dotted));

        // One dot, both halves non-empty, and nothing else exotic.
        assert!(!AdminDatabaseProvider::Supabase.valid_role("postgres."));
        assert!(!AdminDatabaseProvider::Supabase.valid_role(".project"));
        assert!(!AdminDatabaseProvider::Supabase.valid_role("a.b.c"));
        assert!(!AdminDatabaseProvider::Supabase.valid_role("post gres"));
        assert!(AdminDatabaseProvider::Supabase.valid_role("admin_api_runtime"));
    }

    #[test]
    fn hosts_must_belong_to_the_configured_provider() {
        assert_eq!(
            AdminDatabaseProvider::Neon.validate_endpoint(&url(
                "postgres://u@admin-db.example/admin?sslmode=verify-full"
            )),
            Err(ProviderError::HostNotProviderOwned)
        );
        assert_eq!(
            AdminDatabaseProvider::Supabase.validate_endpoint(&url(
                "postgres://u@admin-db.example/admin?sslmode=verify-full"
            )),
            Err(ProviderError::HostNotProviderOwned)
        );
        // RDS keeps exact-host matching and imposes no suffix of its own.
        assert!(
            AdminDatabaseProvider::Rds
                .validate_endpoint(&url(
                    "postgres://u@admin-db.example/admin?sslmode=verify-full"
                ))
                .is_ok()
        );
    }

    #[test]
    fn neon_endpoint_option_must_agree_with_the_hostname() {
        let base = "postgres://u@ep-cool-name-123456.us-east-2.aws.neon.tech/admin";
        assert!(
            AdminDatabaseProvider::Neon
                .validate_endpoint(&url(&format!("{base}?sslmode=verify-full")))
                .is_ok()
        );
        assert!(
            AdminDatabaseProvider::Neon
                .validate_endpoint(&url(&format!(
                    "{base}?sslmode=verify-full&options=endpoint%3Dep-cool-name-123456"
                )))
                .is_ok()
        );
        // Points at a different compute endpoint than the host resolves to.
        assert_eq!(
            AdminDatabaseProvider::Neon.validate_endpoint(&url(&format!(
                "{base}?sslmode=verify-full&options=endpoint%3Dep-other-endpoint-999999"
            ))),
            Err(ProviderError::NeonEndpointMismatch)
        );
        // A neon.tech host with no endpoint label at all.
        assert_eq!(
            AdminDatabaseProvider::Neon.validate_endpoint(&url(
                "postgres://u@console.neon.tech/admin?sslmode=verify-full"
            )),
            Err(ProviderError::NeonEndpointMissing)
        );
    }

    #[test]
    fn supabase_refuses_the_transaction_pooler() {
        let pooler = "postgres://postgres.abcdefghijklmnopqrst@aws-0-us-east-1.pooler.supabase.com";
        assert_eq!(
            AdminDatabaseProvider::Supabase
                .validate_endpoint(&url(&format!("{pooler}:6543/admin?sslmode=verify-full"))),
            Err(ProviderError::SupabaseTransactionPooler)
        );
        assert!(
            AdminDatabaseProvider::Supabase
                .validate_endpoint(&url(&format!("{pooler}:5432/admin?sslmode=verify-full")))
                .is_ok()
        );
        assert!(
            AdminDatabaseProvider::Supabase
                .validate_endpoint(&url(
                    "postgres://postgres@db.abcdefghijklmnopqrst.supabase.co:5432/admin?sslmode=verify-full"
                ))
                .is_ok()
        );
    }
}
