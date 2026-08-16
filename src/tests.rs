use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use mcpg_plugin_protocol::IdentityResolution;
use mcpg_plugin_protocol::types::RequestMetadata;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::{Value, json};

use super::{JwtIdentityPlugin, PLUGIN_ID};

const DESCRIPTOR: &str = include_str!("../plugin.yaml");
const ED_PRIV: &str = include_str!("testdata/ed25519_priv.pem");
const ED_PUB: &str = include_str!("testdata/ed25519_pub.pem");
const RSA_PRIV: &str = include_str!("testdata/rsa_priv.pem");
const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");

const HS_SECRET: &str = "0123456789abcdef-shared-secret";
const ISS: &str = "https://idp.example";

fn build(cfg: Value) -> JwtIdentityPlugin {
    JwtIdentityPlugin::from_config_json(&cfg.to_string())
}

fn sign(alg: Algorithm, key: &EncodingKey, claims: &Value, kid: Option<&str>) -> String {
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    encode(&header, claims, key).expect("sign")
}

fn resolve(p: &JwtIdentityPlugin, token: &str) -> IdentityResolution {
    let headers = vec![("Authorization".to_owned(), format!("Bearer {token}"))];
    p.resolve_identity(&headers, &RequestMetadata::default(), &json!({}))
}

/// A standard HS256 single-issuer plugin (audience `mcpg`).
fn hs_plugin() -> JwtIdentityPlugin {
    build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "algorithms": ["HS256"],
            "allow_hmac": true,
            "key": { "kind": "hs_secret", "secret": HS_SECRET }
        }]
    }))
}

fn hs_key() -> EncodingKey {
    EncodingKey::from_secret(HS_SECRET.as_bytes())
}

fn base_claims() -> Value {
    json!({
        "sub": "alice",
        "iss": ISS,
        "aud": "mcpg",
        "exp": get_current_timestamp() + 3600
    })
}

#[test]
fn no_authorization_header_is_none() {
    let p = hs_plugin();
    let r = p.resolve_identity(&[], &RequestMetadata::default(), &json!({}));
    assert!(matches!(r, IdentityResolution::None));
}

#[test]
fn empty_bearer_token_is_none() {
    let p = hs_plugin();
    let headers = vec![("Authorization".to_owned(), "Bearer ".to_owned())];
    let r = p.resolve_identity(&headers, &RequestMetadata::default(), &json!({}));
    assert!(matches!(r, IdentityResolution::None));
}

#[test]
fn hs256_valid_token_resolves() {
    let p = hs_plugin();
    let token = sign(Algorithm::HS256, &hs_key(), &base_claims(), None);
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.subject_id.as_deref(), Some("alice"));
            assert_eq!(identity.trust_level, "verified");
            assert_eq!(identity.kind, "verified");
            assert_eq!(identity.auth_provider.as_deref(), Some("jwt"));
            assert_eq!(identity.issuer.as_deref(), Some(ISS));
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn hs256_wrong_secret_invalid() {
    let p = hs_plugin();
    let wrong = EncodingKey::from_secret(b"a-totally-different-secret-value");
    let token = sign(Algorithm::HS256, &wrong, &base_claims(), None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn expired_token_invalid() {
    let p = hs_plugin();
    let mut c = base_claims();
    c["exp"] = json!(get_current_timestamp() - 3600);
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn nbf_in_future_invalid() {
    let p = hs_plugin();
    let mut c = base_claims();
    c["nbf"] = json!(get_current_timestamp() + 3600);
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn wrong_iss_invalid() {
    let p = hs_plugin();
    let mut c = base_claims();
    c["iss"] = json!("https://evil.example");
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn missing_aud_when_required_invalid() {
    let p = hs_plugin();
    let mut c = base_claims();
    c.as_object_mut().unwrap().remove("aud");
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn wrong_aud_invalid() {
    let p = hs_plugin();
    let mut c = base_claims();
    c["aud"] = json!("some-other-service");
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn disallowed_alg_invalid() {
    // Issuer accepts only RS256 (RSA public key), but the token is HS256.
    let p = build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "algorithms": ["RS256"],
            "key": { "kind": "rsa_pem", "pem": RSA_PUB }
        }]
    }));
    let token = sign(Algorithm::HS256, &hs_key(), &base_claims(), None);
    match resolve(&p, &token) {
        IdentityResolution::Invalid { reason, .. } => {
            assert!(reason.contains("not allowed"), "{reason}")
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn alg_none_rejected() {
    let p = hs_plugin();
    let b64 = |v: &Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    let header = b64(&json!({ "alg": "none", "typ": "JWT" }));
    let payload = b64(&base_claims());
    let token = format!("{header}.{payload}.");
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn claim_mapping_full() {
    let p = build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "algorithms": ["HS256"],
            "allow_hmac": true,
            "key": { "kind": "hs_secret", "secret": HS_SECRET },
            "claim_mappings": {
                "role_claim_paths": ["realm_access.roles"],
                "group_claim_paths": ["groups"],
                "scope_claim_paths": ["scope"],
                "attribute_claim_mappings": { "email": "email" }
            }
        }]
    }));
    let mut c = base_claims();
    let obj = c.as_object_mut().unwrap();
    obj.insert("realm_access".into(), json!({ "roles": ["admin", "dev"] }));
    obj.insert("groups".into(), json!(["g1", "g2"]));
    obj.insert("scope".into(), json!("read write"));
    obj.insert("email".into(), json!("alice@example.com"));
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.roles, vec!["admin", "dev"]);
            assert_eq!(identity.groups, vec!["g1", "g2"]);
            assert_eq!(identity.scopes, vec!["read", "write"]);
            assert_eq!(
                identity.attributes.get("email").unwrap(),
                "alice@example.com"
            );
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn missing_sub_invalid() {
    let p = hs_plugin();
    let mut c = base_claims();
    c.as_object_mut().unwrap().remove("sub");
    let token = sign(Algorithm::HS256, &hs_key(), &c, None);
    match resolve(&p, &token) {
        IdentityResolution::Invalid { reason, .. } => {
            assert!(reason.contains("subject"), "{reason}")
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn rs256_resolves() {
    let p = build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "algorithms": ["RS256"],
            "key": { "kind": "rsa_pem", "pem": RSA_PUB }
        }]
    }));
    let key = EncodingKey::from_rsa_pem(RSA_PRIV.as_bytes()).unwrap();
    let token = sign(Algorithm::RS256, &key, &base_claims(), Some("rsa-1"));
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Resolved { .. }
    ));
}

#[test]
fn eddsa_resolves() {
    let p = build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "algorithms": ["EdDSA"],
            "key": { "kind": "ed_pem", "pem": ED_PUB }
        }]
    }));
    let key = EncodingKey::from_ed_pem(ED_PRIV.as_bytes()).unwrap();
    let token = sign(Algorithm::EdDSA, &key, &base_claims(), None);
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Resolved { .. }
    ));
}

#[test]
fn multi_issuer_routing() {
    let p = build(json!({
        "issuers": [
            {
                "issuer": "https://a.example", "audiences": ["mcpg"],
                "algorithms": ["HS256"], "allow_hmac": true,
                "key": { "kind": "hs_secret", "secret": "aaaaaaaaaaaaaaaa-secret-a" }
            },
            {
                "issuer": "https://b.example", "audiences": ["mcpg"],
                "algorithms": ["HS256"], "allow_hmac": true,
                "key": { "kind": "hs_secret", "secret": "bbbbbbbbbbbbbbbb-secret-b" }
            }
        ]
    }));
    let key_b = EncodingKey::from_secret(b"bbbbbbbbbbbbbbbb-secret-b");
    let claims = json!({
        "sub": "bob", "iss": "https://b.example", "aud": "mcpg",
        "exp": get_current_timestamp() + 3600
    });
    let token = sign(Algorithm::HS256, &key_b, &claims, None);
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.issuer.as_deref(), Some("https://b.example"));
            assert_eq!(identity.subject_id.as_deref(), Some("bob"));
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn header_asserted_trust_propagates() {
    let p = build(json!({
        "issuers": [{
            "issuer": ISS, "audiences": ["mcpg"],
            "algorithms": ["HS256"], "allow_hmac": true,
            "key": { "kind": "hs_secret", "secret": HS_SECRET }
        }],
        "resolution": { "trust_level": "header_asserted" }
    }));
    let token = sign(Algorithm::HS256, &hs_key(), &base_claims(), None);
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.trust_level, "header_asserted");
            assert_eq!(identity.kind, "header_asserted");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn custom_header_token_source() {
    let p = build(json!({
        "token_source": { "kind": "custom_header", "header_name": "X-Token" },
        "issuers": [{
            "issuer": ISS, "audiences": ["mcpg"],
            "algorithms": ["HS256"], "allow_hmac": true,
            "key": { "kind": "hs_secret", "secret": HS_SECRET }
        }]
    }));
    let token = sign(Algorithm::HS256, &hs_key(), &base_claims(), None);
    let headers = vec![("X-Token".to_owned(), token)];
    assert!(matches!(
        p.resolve_identity(&headers, &RequestMetadata::default(), &json!({})),
        IdentityResolution::Resolved { .. }
    ));
}

#[test]
fn descriptor_yaml_is_well_formed() {
    assert!(DESCRIPTOR.contains(&format!("id: {PLUGIN_ID}")));
    assert!(DESCRIPTOR.contains("class: identity_provider"));
    assert!(DESCRIPTOR.contains("runtime: native-cdylib-v1"));
    assert!(DESCRIPTOR.contains("required_capabilities: []"));
}

#[test]
fn manifest_id_and_class() {
    use mcpg_plugin_protocol::PluginClass;
    let p = hs_plugin();
    let m = SyncIdentityResolver::manifest(&p);
    assert_eq!(m.id, PLUGIN_ID);
    assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
    assert!(m.required_capabilities.is_empty());
}

#[test]
#[should_panic(expected = "refusing to load")]
fn factory_panics_on_unparseable_config() {
    let _ = JwtIdentityPlugin::from_config_json("not-json");
}
