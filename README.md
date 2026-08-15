# Generic JWT Identity Resolver (`dev.mcpg.identity.jwt`)

An **identity_provider** that resolves the caller's identity from a **bearer JWT**
verified against operator-supplied **static keys** — for issuers that are not
full OIDC providers (no discovery endpoint, no live JWKS URL). It validates the
signature and the `exp`/`nbf`/`iss`/`aud` claims, then maps token claims to
`subject_id` / roles / groups / scopes / attributes.

**No discovery, no JWKS fetch, no introspection, no network.** Every path is
pure synchronous compute; the IANA-free crypto runs on `aws-lc-rs` (rustls-clean,
no OpenSSL). Keys are parsed **once at boot**. The plugin **fails closed**: a bad
config or an unloadable key refuses to register.

For a provider with a live discovery/JWKS endpoint, use `dev.mcpg.identity.oidc`
instead — this plugin is the static-key, offline counterpart.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `token_source` | object | `Authorization: Bearer` | Where the token comes from (see below). |
| `issuers` | array | *(required, ≥1)* | One or more issuer verification profiles. |
| `resolution.trust_level` | `verified` \| `header_asserted` | `verified` | Trust bucket for a resolved identity. |
| `resolution.auth_provider_label` | string | `jwt` | `auth_provider` on the resolved identity. |

### `token_source`

| Field | Type | Description |
|---|---|---|
| `kind` | `authorization_bearer` \| `custom_header` | Default `authorization_bearer` (the `Authorization: Bearer <jwt>` header). |
| `header_name` | string | For `custom_header`, the header to read (e.g. `X-Token`). |
| `header_prefix` | string | Prefix to strip (default `Bearer ` for bearer, empty for custom). |

### Each `issuers[]` entry

| Field | Type | Default | Description |
|---|---|---|---|
| `issuer` | string | *(required)* | Exact `iss` claim to match (need not be a URL). |
| `audiences` | array of string | `[]` | Accepted `aud` values. Empty requires `allow_any_audience: true`. |
| `allow_any_audience` | bool | `false` | Opt out of `aud` validation (a token minted for another service would otherwise verify — leave false in production). |
| `algorithms` | array of string | *(required, ≥1)* | Allowed `alg`s, e.g. `RS256`, `ES256`, `EdDSA`, `HS256`. |
| `allow_hmac` | bool | `false` | Required to use any HS* algorithm (a shared secret crosses the trust boundary). |
| `key` | object | *(required)* | Static key material (see below). |
| `clock_skew_secs` | int ≤ 300 | `60` | `exp`/`nbf` leeway. A large value is a replay window, not drift tolerance. |
| `required_claims` | array of string | `[]` | Extra spec claims forced present beyond `exp`/`iss`[/`aud`]. |
| `claim_mappings` | object | *(see below)* | How claims map to the resolved identity. |

### `key` (one of)

| `kind` | Field | For |
|---|---|---|
| `hs_secret` | `secret` (≥16 bytes) | HS256/384/512 (requires `allow_hmac`). |
| `rsa_pem` | `pem` (public key PEM) | RS*/PS*. |
| `ec_pem` | `pem` (public key PEM) | ES*. |
| `ed_pem` | `pem` (public key PEM) | EdDSA. |
| `jwks` | `jwks_json` (a static JWKS document) | Any; per-key `kid` is honoured. |

### `claim_mappings`

| Field | Default | Description |
|---|---|---|
| `subject_claim` | `sub` | Claim → `subject_id` (missing/empty ⇒ token rejected). |
| `role_claim_paths` | `[]` | Dotted paths (e.g. `realm_access.roles`) → roles. |
| `group_claim_paths` | `[]` | → groups. |
| `scope_claim_paths` | `["scope","scp"]` | → scopes (space-separated strings are split). |
| `attribute_claim_mappings` | `{}` | `{claim → attribute_name}` string claims → attributes. |

All structs reject unknown fields. (Operator claim mappings must not emit
`__mcpg_*` attributes — the host reserves that namespace for its FFI identity
integrity tag.)

## Example

```yaml
plugins:
  - id: dev.mcpg.identity.jwt
    class: identity_provider
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/identity-jwt:protocol-1" }
    config:
      issuers:
        - issuer: https://auth.partner.example
          audiences: ["https://gateway.mcpg.dev"]
          algorithms: ["EdDSA"]
          key:
            kind: ed_pem
            pem: ${env.PARTNER_JWT_ED25519_PUBLIC_PEM}
          claim_mappings:
            role_claim_paths: ["realm_access.roles"]
            scope_claim_paths: ["scope"]
            attribute_claim_mappings: { tenant: "tenant" }
```

A request bearing a valid EdDSA JWT from that issuer resolves to a **verified**
identity carrying the token's `sub`, roles, scopes, and `tenant` attribute.

## Notes

- HS* require `allow_hmac: true` — a symmetric secret shared across the trust
  boundary is rarely appropriate for inbound identity.
- `aud` and `iss` are required spec claims (when configured), so a token omitting
  them is hard-rejected — not silently accepted.
- Pure-Rust (`jsonwebtoken` on `aws-lc-rs`, MIT/Apache-2.0), rustls-clean,
  `default-members`. No host capabilities required.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
