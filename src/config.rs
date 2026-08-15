//! Operator-supplied configuration for `dev.mcpg.identity.jwt`.
//!
//! Mirrors the OIDC plugin's token-source + claim-mapping shape, but drops
//! every network path (discovery / JWKS-fetch / introspection): keys are STATIC
//! and supplied inline. All structs reject unknown fields.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Hard upper bound on `clock_skew_secs`. Beyond a few minutes the leeway stops
/// being clock-drift tolerance and becomes a token-replay window.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Minimum HS shared-secret length. A short secret is brute-forceable.
const MIN_HS_SECRET_BYTES: usize = 16;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    #[serde(default)]
    pub token_source: TokenSourceConfig,
    pub issuers: Vec<IssuerConfig>,
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

impl JwtConfig {
    pub fn parse(s: &str) -> Result<Self> {
        let cfg: Self = serde_json::from_str(s).context("invalid identity.jwt config JSON")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.issuers.is_empty() {
            return Err(anyhow::anyhow!("identity.jwt: `issuers` must be non-empty"));
        }
        let mut seen = std::collections::HashSet::new();
        for (i, issuer) in self.issuers.iter().enumerate() {
            issuer
                .validate()
                .with_context(|| format!("identity.jwt: issuers[{i}]"))?;
            if !seen.insert(issuer.issuer.clone()) {
                return Err(anyhow::anyhow!(
                    "identity.jwt: duplicate issuer '{}'",
                    issuer.issuer
                ));
            }
        }
        self.resolution.validate()?;
        Ok(())
    }
}

// --- token source (identical shape to oidc::TokenSourceConfig) ---------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSourceConfig {
    #[serde(default = "default_token_source_kind")]
    pub kind: TokenSourceKind,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_prefix: Option<String>,
}

impl Default for TokenSourceConfig {
    fn default() -> Self {
        Self {
            kind: TokenSourceKind::AuthorizationBearer,
            header_name: None,
            header_prefix: None,
        }
    }
}

impl TokenSourceConfig {
    pub fn effective_header_name(&self) -> &str {
        match self.kind {
            TokenSourceKind::AuthorizationBearer => "authorization",
            TokenSourceKind::CustomHeader => self.header_name.as_deref().unwrap_or("authorization"),
        }
    }

    pub fn effective_header_prefix(&self) -> &str {
        if let Some(ref prefix) = self.header_prefix {
            return prefix;
        }
        match self.kind {
            TokenSourceKind::AuthorizationBearer => "Bearer ",
            TokenSourceKind::CustomHeader => "",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenSourceKind {
    AuthorizationBearer,
    CustomHeader,
}

fn default_token_source_kind() -> TokenSourceKind {
    TokenSourceKind::AuthorizationBearer
}

// --- issuer ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// Exact `iss` claim string to match. Not required to be a URL (non-OIDC
    /// issuers may use opaque names).
    pub issuer: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Allowed signing algorithms (e.g. `RS256`, `EdDSA`, `HS256`). HS* require
    /// `allow_hmac: true`.
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub allow_hmac: bool,
    pub key: KeyMaterialConfig,
    #[serde(default)]
    pub claim_mappings: ClaimMappingConfig,
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Explicit opt-in to skip audience validation. Empty `audiences` without
    /// this is a hard error (a token minted for another service would verify).
    #[serde(default)]
    pub allow_any_audience: bool,
    /// Extra registered/spec claims forced present beyond `exp`/`iss`[/`aud`].
    #[serde(default)]
    pub required_claims: Vec<String>,
}

impl IssuerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(anyhow::anyhow!("issuer must not be empty"));
        }
        if self.algorithms.is_empty() {
            return Err(anyhow::anyhow!("algorithms must not be empty"));
        }
        for alg in &self.algorithms {
            parse_algorithm(alg)?;
            if is_hmac_alg(alg) && !self.allow_hmac {
                return Err(anyhow::anyhow!(
                    "algorithms contains HMAC algorithm '{alg}'; set allow_hmac=true only if \
                     your issuer signs with HS* (a shared secret crosses the trust boundary)"
                ));
            }
        }
        if self.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(anyhow::anyhow!(
                "clock_skew_secs {} exceeds the maximum {}s — a larger leeway is a token \
                 replay window, not clock-drift tolerance",
                self.clock_skew_secs,
                MAX_CLOCK_SKEW_SECS
            ));
        }
        if self.audiences.is_empty() && !self.allow_any_audience {
            return Err(anyhow::anyhow!(
                "audiences is empty — refusing to skip `aud` validation (a token minted for \
                 another service would be accepted). Set `audiences`, or for the rare issuer \
                 that issues no audience claim opt in with `allow_any_audience: true`"
            ));
        }
        self.key.validate()?;
        Ok(())
    }
}

fn default_clock_skew_secs() -> u64 {
    60
}

/// Returns true for HMAC symmetric algorithms (HS256/HS384/HS512).
pub fn is_hmac_alg(name: &str) -> bool {
    matches!(name, "HS256" | "HS384" | "HS512")
}

/// Parse an algorithm name into a jsonwebtoken `Algorithm`.
pub fn parse_algorithm(name: &str) -> Result<jsonwebtoken::Algorithm> {
    use jsonwebtoken::Algorithm::*;
    Ok(match name {
        "RS256" => RS256,
        "RS384" => RS384,
        "RS512" => RS512,
        "PS256" => PS256,
        "PS384" => PS384,
        "PS512" => PS512,
        "ES256" => ES256,
        "ES384" => ES384,
        "EdDSA" => EdDSA,
        "HS256" => HS256,
        "HS384" => HS384,
        "HS512" => HS512,
        other => return Err(anyhow::anyhow!("unsupported algorithm: '{other}'")),
    })
}

// --- key material (all STATIC, no http) --------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyMaterialConfig {
    /// HS256/384/512 shared secret (raw UTF-8 bytes).
    HsSecret { secret: String },
    /// RSA public key PEM (RS*/PS*).
    RsaPem { pem: String },
    /// EC public key PEM (ES*).
    EcPem { pem: String },
    /// Ed25519 public key PEM (EdDSA).
    EdPem { pem: String },
    /// A static JWKS document (JSON). Each key may carry a `kid`.
    Jwks { jwks_json: String },
}

impl KeyMaterialConfig {
    fn validate(&self) -> Result<()> {
        match self {
            KeyMaterialConfig::HsSecret { secret } => {
                if secret.len() < MIN_HS_SECRET_BYTES {
                    return Err(anyhow::anyhow!(
                        "hs_secret must be at least {MIN_HS_SECRET_BYTES} bytes"
                    ));
                }
            }
            KeyMaterialConfig::RsaPem { pem }
            | KeyMaterialConfig::EcPem { pem }
            | KeyMaterialConfig::EdPem { pem } => {
                if !pem.contains("-----BEGIN") {
                    return Err(anyhow::anyhow!("key PEM must contain a -----BEGIN marker"));
                }
            }
            KeyMaterialConfig::Jwks { jwks_json } => {
                let set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(jwks_json)
                    .context("jwks_json is not a parseable JWKS document")?;
                if set.keys.is_empty() {
                    return Err(anyhow::anyhow!("jwks_json contains no keys"));
                }
            }
        }
        Ok(())
    }
}

// --- claim mappings (identical to oidc) --------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimMappingConfig {
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default)]
    pub group_claim_paths: Vec<String>,
    #[serde(default)]
    pub role_claim_paths: Vec<String>,
    #[serde(default = "default_scope_claim_paths")]
    pub scope_claim_paths: Vec<String>,
    #[serde(default)]
    pub attribute_claim_mappings: BTreeMap<String, String>,
}

impl Default for ClaimMappingConfig {
    fn default() -> Self {
        Self {
            subject_claim: default_subject_claim(),
            group_claim_paths: vec![],
            role_claim_paths: vec![],
            scope_claim_paths: default_scope_claim_paths(),
            attribute_claim_mappings: BTreeMap::new(),
        }
    }
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}
fn default_scope_claim_paths() -> Vec<String> {
    vec!["scope".to_owned(), "scp".to_owned()]
}

// --- resolution --------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

impl ResolutionConfig {
    fn validate(&self) -> Result<()> {
        if !matches!(self.trust_level.as_str(), "verified" | "header_asserted") {
            return Err(anyhow::anyhow!(
                "resolution.trust_level must be `verified` or `header_asserted`, got '{}'",
                self.trust_level
            ));
        }
        Ok(())
    }
}

fn default_trust_level() -> String {
    "verified".to_owned()
}
fn default_auth_provider_label() -> String {
    "jwt".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hs_issuer() -> serde_json::Value {
        json!({
            "issuer": "https://idp.example",
            "audiences": ["mcpg"],
            "algorithms": ["HS256"],
            "allow_hmac": true,
            "key": { "kind": "hs_secret", "secret": "0123456789abcdef0123" }
        })
    }

    #[test]
    fn minimal_hs_config_parses() {
        let cfg = JwtConfig::parse(&json!({ "issuers": [hs_issuer()] }).to_string()).unwrap();
        assert_eq!(cfg.issuers.len(), 1);
        assert_eq!(cfg.resolution.trust_level, "verified");
        assert_eq!(cfg.token_source.effective_header_prefix(), "Bearer ");
    }

    #[test]
    fn deny_unknown_top_level_and_misspelled_audiences() {
        assert!(
            JwtConfig::parse(&json!({ "issuers": [hs_issuer()], "bogus": 1 }).to_string()).is_err()
        );
        let mut iss = hs_issuer();
        iss.as_object_mut().unwrap().remove("audiences");
        iss.as_object_mut()
            .unwrap()
            .insert("audiances".into(), json!(["mcpg"]));
        assert!(JwtConfig::parse(&json!({ "issuers": [iss] }).to_string()).is_err());
    }

    #[test]
    fn empty_issuers_and_duplicate_issuer_rejected() {
        assert!(JwtConfig::parse(&json!({ "issuers": [] }).to_string()).is_err());
        let err = JwtConfig::parse(&json!({ "issuers": [hs_issuer(), hs_issuer()] }).to_string())
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate issuer"), "{err}");
    }

    #[test]
    fn hmac_requires_opt_in() {
        let mut iss = hs_issuer();
        iss.as_object_mut()
            .unwrap()
            .insert("allow_hmac".into(), json!(false));
        // `{:#}` renders the full anyhow cause chain (the HMAC message is the
        // wrapped source under the `issuers[0]` context).
        let err = format!(
            "{:#}",
            JwtConfig::parse(&json!({ "issuers": [iss] }).to_string()).unwrap_err()
        );
        assert!(err.contains("HMAC"), "{err}");
        // opt-in passes
        JwtConfig::parse(&json!({ "issuers": [hs_issuer()] }).to_string()).unwrap();
    }

    #[test]
    fn clock_skew_bound_enforced() {
        let mut iss = hs_issuer();
        iss.as_object_mut()
            .unwrap()
            .insert("clock_skew_secs".into(), json!(301));
        assert!(JwtConfig::parse(&json!({ "issuers": [iss] }).to_string()).is_err());
        let mut ok = hs_issuer();
        ok.as_object_mut()
            .unwrap()
            .insert("clock_skew_secs".into(), json!(300));
        JwtConfig::parse(&json!({ "issuers": [ok] }).to_string()).unwrap();
    }

    #[test]
    fn empty_audiences_needs_opt_in() {
        let mut iss = hs_issuer();
        iss.as_object_mut()
            .unwrap()
            .insert("audiences".into(), json!([]));
        assert!(JwtConfig::parse(&json!({ "issuers": [iss.clone()] }).to_string()).is_err());
        iss.as_object_mut()
            .unwrap()
            .insert("allow_any_audience".into(), json!(true));
        JwtConfig::parse(&json!({ "issuers": [iss] }).to_string()).unwrap();
    }

    #[test]
    fn short_hs_secret_rejected() {
        let mut iss = hs_issuer();
        iss.as_object_mut().unwrap().insert(
            "key".into(),
            json!({ "kind": "hs_secret", "secret": "short" }),
        );
        assert!(JwtConfig::parse(&json!({ "issuers": [iss] }).to_string()).is_err());
    }

    #[test]
    fn pem_without_marker_and_bad_jwks_rejected() {
        let mut rsa = hs_issuer();
        rsa.as_object_mut()
            .unwrap()
            .insert("algorithms".into(), json!(["RS256"]));
        rsa.as_object_mut()
            .unwrap()
            .insert("allow_hmac".into(), json!(false));
        rsa.as_object_mut().unwrap().insert(
            "key".into(),
            json!({ "kind": "rsa_pem", "pem": "not-a-pem" }),
        );
        assert!(JwtConfig::parse(&json!({ "issuers": [rsa] }).to_string()).is_err());

        let mut jwks = hs_issuer();
        jwks.as_object_mut()
            .unwrap()
            .insert("algorithms".into(), json!(["RS256"]));
        jwks.as_object_mut()
            .unwrap()
            .insert("allow_hmac".into(), json!(false));
        jwks.as_object_mut().unwrap().insert(
            "key".into(),
            json!({ "kind": "jwks", "jwks_json": "{ not json" }),
        );
        assert!(JwtConfig::parse(&json!({ "issuers": [jwks] }).to_string()).is_err());
    }

    #[test]
    fn bad_trust_level_rejected() {
        let v = json!({ "issuers": [hs_issuer()], "resolution": { "trust_level": "root" } });
        assert!(JwtConfig::parse(&v.to_string()).is_err());
    }
}
