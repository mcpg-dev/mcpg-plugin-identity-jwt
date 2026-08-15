//! `dev.mcpg.identity.jwt` — generic static-key JWT identity_provider.
//!
//! Verifies non-OIDC bearer JWTs against operator-supplied STATIC keys (HS256
//! shared secret, RS/ES/EdDSA public-key PEM, or a static JWKS document),
//! validates signature + `exp`/`nbf`/`iss`/`aud`, and maps claims to
//! roles/groups/scopes/attributes. No OIDC discovery, no JWKS fetch, no
//! introspection — every path is pure synchronous compute with NO network.
//!
//! Reuses the OIDC plugin's verify + claim-mapping logic minus all async I/O.
//! Fails closed on bad config (a misconfigured identity resolver is a security
//! hole; it refuses to load).

pub mod config;

use std::sync::Arc;

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mcpg_plugin_protocol::types::RequestMetadata;
use mcpg_plugin_protocol::{
    IdentityResolution, PluginIdentity, PluginManifest, firstparty_manifest,
};
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::Value;
use std::collections::BTreeMap;
use tracing::{debug, info_span, warn};

pub use config::{
    ClaimMappingConfig, IssuerConfig, JwtConfig, KeyMaterialConfig, ResolutionConfig,
    TokenSourceConfig, parse_algorithm,
};

const PLUGIN_ID: &str = "dev.mcpg.identity.jwt";

/// One decoding key with its (optional) declared algorithm + `kid`.
struct KeyEntry {
    kid: Option<String>,
    key: DecodingKey,
    algorithm: Option<Algorithm>,
}

/// A config issuer with its keys parsed + algorithms resolved at boot.
struct CompiledIssuer {
    issuer: String,
    audiences: Vec<String>,
    allowed_algs: Vec<Algorithm>,
    keys: Vec<KeyEntry>,
    clock_skew_secs: u64,
    required_claims: Vec<String>,
    claim_mappings: ClaimMappingConfig,
}

pub struct JwtIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    token_source: TokenSourceConfig,
    issuers: Vec<CompiledIssuer>,
    resolution: ResolutionConfig,
}

/// Map a JWKS `KeyAlgorithm` to a jsonwebtoken `Algorithm`.
fn map_key_algorithm(ka: jsonwebtoken::jwk::KeyAlgorithm) -> Option<Algorithm> {
    use jsonwebtoken::jwk::KeyAlgorithm;
    Some(match ka {
        KeyAlgorithm::HS256 => Algorithm::HS256,
        KeyAlgorithm::HS384 => Algorithm::HS384,
        KeyAlgorithm::HS512 => Algorithm::HS512,
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        _ => return None,
    })
}

/// Build the decoding keys for one issuer's static key material.
fn build_keys(km: &KeyMaterialConfig) -> anyhow::Result<Vec<KeyEntry>> {
    Ok(match km {
        KeyMaterialConfig::HsSecret { secret } => vec![KeyEntry {
            kid: None,
            key: DecodingKey::from_secret(secret.as_bytes()),
            algorithm: None,
        }],
        KeyMaterialConfig::RsaPem { pem } => vec![KeyEntry {
            kid: None,
            key: DecodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("invalid RSA public-key PEM: {e}"))?,
            algorithm: None,
        }],
        KeyMaterialConfig::EcPem { pem } => vec![KeyEntry {
            kid: None,
            key: DecodingKey::from_ec_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("invalid EC public-key PEM: {e}"))?,
            algorithm: None,
        }],
        KeyMaterialConfig::EdPem { pem } => vec![KeyEntry {
            kid: None,
            key: DecodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("invalid Ed25519 public-key PEM: {e}"))?,
            algorithm: None,
        }],
        KeyMaterialConfig::Jwks { jwks_json } => {
            let set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(jwks_json)
                .map_err(|e| anyhow::anyhow!("unparseable JWKS: {e}"))?;
            let mut keys = Vec::new();
            for jwk in &set.keys {
                match DecodingKey::from_jwk(jwk) {
                    Ok(key) => keys.push(KeyEntry {
                        kid: jwk.common.key_id.clone(),
                        key,
                        algorithm: jwk.common.key_algorithm.and_then(map_key_algorithm),
                    }),
                    Err(e) => warn!(error = %e, "identity.jwt: skipping unusable JWKS key"),
                }
            }
            if keys.is_empty() {
                return Err(anyhow::anyhow!("JWKS produced no usable decoding keys"));
            }
            keys
        }
    })
}

impl JwtIdentityPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = JwtConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "identity.jwt: config parse failed; refusing to register"
            );
            panic!(
                "identity.jwt config parse failed: {err}. A misconfigured identity \
                 resolver is a security hole; refusing to load rather than falling \
                 back to defaults. Fix operator config and retry."
            )
        });

        let issuers = cfg
            .issuers
            .into_iter()
            .map(compile_issuer)
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap_or_else(|err| {
                tracing::error!(
                    plugin_id = PLUGIN_ID,
                    error = %err,
                    "identity.jwt: key compile failed; refusing to register"
                );
                panic!(
                    "identity.jwt config parse failed: {err}. A misconfigured identity \
                     resolver is a security hole; refusing to load."
                )
            });

        tracing::info!(
            plugin_id = PLUGIN_ID,
            issuers_loaded = issuers.len(),
            "identity.jwt: registry compiled"
        );

        Self {
            inner: Arc::new(Inner {
                manifest: firstparty_manifest! {
                    id: PLUGIN_ID,
                    name: "Generic JWT Identity Resolver",
                    class: IdentityProvider,
                },
                token_source: cfg.token_source,
                issuers,
                resolution: cfg.resolution,
            }),
        }
    }
}

fn compile_issuer(ic: IssuerConfig) -> anyhow::Result<CompiledIssuer> {
    let allowed_algs = ic
        .algorithms
        .iter()
        .map(|a| parse_algorithm(a))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let keys = build_keys(&ic.key)?;
    Ok(CompiledIssuer {
        issuer: ic.issuer,
        audiences: ic.audiences,
        allowed_algs,
        keys,
        clock_skew_secs: ic.clock_skew_secs,
        required_claims: ic.required_claims,
        claim_mappings: ic.claim_mappings,
    })
}

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!("mcpg_identity_jwt_resolutions_total", "outcome" => outcome).increment(1);
    metrics::histogram!("mcpg_identity_jwt_resolve_ms").record(elapsed.as_millis() as f64);
    if let IdentityResolution::Invalid { reason } = result {
        warn!(reason = %reason, "identity.jwt: invalid token");
    }
}

/// Extract the bearer token from the configured header.
fn extract_token(token_source: &TokenSourceConfig, headers: &[(String, String)]) -> Option<String> {
    let value = lookup_header(headers, token_source.effective_header_name())?;
    let prefix = token_source.effective_header_prefix();
    let rest = if prefix.is_empty() {
        Some(value)
    } else {
        strip_ascii_prefix(value, prefix)
    }?;
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_owned())
    }
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(target).then_some(value.as_str()))
}

fn strip_ascii_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    let (head, tail) = s.split_at(prefix.len());
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

/// Read the unverified `iss` from a JWT payload (to route to the right issuer).
fn extract_unverified_issuer(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    claims.get("iss").and_then(|v| v.as_str()).map(String::from)
}

fn resolve(inner: &Inner, headers: &[(String, String)]) -> IdentityResolution {
    let token = match extract_token(&inner.token_source, headers) {
        Some(t) => t,
        None => return IdentityResolution::None,
    };

    // Route to the issuer matching the token's (unverified) `iss`; the signature
    // + `set_issuer` binding below is what actually authenticates it.
    if let Some(iss) = extract_unverified_issuer(&token)
        && let Some(ci) = inner.issuers.iter().find(|c| c.issuer == iss)
    {
        return verify_against_issuer(ci, &token, &inner.resolution);
    }

    // No declared/matching iss — try each configured issuer; signature +
    // issuer-binding still gate acceptance.
    let mut last = IdentityResolution::Invalid {
        reason: "no configured issuer matched the token".to_owned(),
    };
    for ci in &inner.issuers {
        match verify_against_issuer(ci, &token, &inner.resolution) {
            resolved @ IdentityResolution::Resolved { .. } => return resolved,
            other => last = other,
        }
    }
    last
}

fn verify_against_issuer(
    ci: &CompiledIssuer,
    token: &str,
    resolution: &ResolutionConfig,
) -> IdentityResolution {
    let header = match decode_header(token) {
        Ok(h) => h,
        // jsonwebtoken has no `none` Algorithm variant, so an `alg: none` token
        // fails to parse here — alg=none is rejected by construction.
        Err(e) => {
            return IdentityResolution::Invalid {
                reason: format!("invalid JWT header: {e}"),
            };
        }
    };

    if !ci.allowed_algs.contains(&header.alg) {
        return IdentityResolution::Invalid {
            reason: format!(
                "algorithm {:?} not allowed for issuer '{}'",
                header.alg, ci.issuer
            ),
        };
    }

    // Candidate keys: prefer a kid match; fall back to untagged static keys
    // (single HS/PEM keys carry no kid); if no kid on the token, try all.
    let candidates: Vec<&KeyEntry> = match &header.kid {
        Some(kid) => {
            let matched: Vec<&KeyEntry> = ci
                .keys
                .iter()
                .filter(|k| k.kid.as_deref() == Some(kid.as_str()))
                .collect();
            if matched.is_empty() {
                ci.keys.iter().filter(|k| k.kid.is_none()).collect()
            } else {
                matched
            }
        }
        None => ci.keys.iter().collect(),
    };
    if candidates.is_empty() {
        return IdentityResolution::Invalid {
            reason: format!("no key found for kid {:?}", header.kid),
        };
    }

    for key in candidates {
        let alg = key.algorithm.unwrap_or(header.alg);
        let mut validation = Validation::new(alg);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = ci.clock_skew_secs;
        validation.set_issuer(&[ci.issuer.as_str()]);

        // `set_issuer`/`set_audience` only check a claim when PRESENT; force
        // `iss` (and `aud` when configured) into required_spec_claims so a token
        // omitting the claim is hard-rejected.
        let mut required: Vec<String> = vec!["exp".to_owned(), "iss".to_owned()];
        if ci.audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&ci.audiences);
            required.push("aud".to_owned());
        }
        required.extend(ci.required_claims.iter().cloned());
        validation.set_required_spec_claims(&required);

        match decode::<Value>(token, &key.key, &validation) {
            Ok(data) => return map_claims(ci, &data.claims, resolution),
            Err(e) => {
                debug!(issuer = %ci.issuer, error = %e, "identity.jwt: key did not verify, trying next");
                continue;
            }
        }
    }

    IdentityResolution::Invalid {
        reason: "token signature verification failed".to_owned(),
    }
}

fn map_claims(
    ci: &CompiledIssuer,
    claims: &Value,
    resolution: &ResolutionConfig,
) -> IdentityResolution {
    let m = &ci.claim_mappings;
    let subject_id = match extract_string_claim(claims, &m.subject_claim) {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return IdentityResolution::Invalid {
                reason: format!("missing or empty '{}' (subject) claim", m.subject_claim),
            };
        }
    };
    let groups = extract_string_list_claims(claims, &m.group_claim_paths);
    let roles = extract_string_list_claims(claims, &m.role_claim_paths);
    let scopes = extract_string_list_claims(claims, &m.scope_claim_paths);
    let mut attributes = BTreeMap::new();
    for (claim_name, attr_name) in &m.attribute_claim_mappings {
        if let Some(v) = extract_string_claim(claims, claim_name) {
            attributes.insert(attr_name.clone(), v);
        }
    }

    IdentityResolution::Resolved {
        identity: PluginIdentity {
            kind: resolution.trust_level.clone(),
            trust_level: resolution.trust_level.clone(),
            subject_id: Some(subject_id),
            auth_provider: Some(resolution.auth_provider_label.clone()),
            issuer: Some(ci.issuer.clone()),
            roles,
            groups,
            scopes,
            attributes,
        },
    }
}

fn extract_string_claim(claims: &Value, path: &str) -> Option<String> {
    resolve_json_path(claims, path)?.as_str().map(String::from)
}

fn extract_string_list_claims(claims: &Value, paths: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for path in paths {
        if let Some(value) = resolve_json_path(claims, path) {
            match value {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            result.push(s.to_owned());
                        }
                    }
                }
                Value::String(s) => {
                    for part in s.split_whitespace() {
                        result.push(part.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    result
}

fn resolve_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

impl SyncIdentityResolver for JwtIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_jwt_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.identity.jwt",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: JwtIdentityPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> JwtIdentityPlugin {
                JwtIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests;
