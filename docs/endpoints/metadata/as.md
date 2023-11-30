Authorization Servers publishing metadata `MUST` make a JSON document available at the path formed by concatenating the
string `/.well-known/oauth-authorization-server` to the `Authorization Server Issuer Identifier`. If the Authorization
Servers Issuer value contains a path component, any terminating / `MUST` be removed before
appending `/.well-known/oauth-authorization-server`.

Authorization Server Metadata parameters are discussed in [RFC 8414] Section 2

|Claim|Description|Reference|
|:----|:----|:----|
|`issuer`|The Authorization Server Issuer Identifier, which is a URL that uses the "https" scheme and has no query or fragment components.|[RFC 8414]|
|`authorization_endpoint`|URL of the authorization server's authorization endpoint.|[RFC 8414], [RFC 6749]|
|`token_endpoint`|URL of the authorization server's token endpoint.|[RFC 8414], [RFC 6749]|
|`jwks_uri`|URL of the authorization server's JWK Set. The referenced document contains the signing key(s) the client uses to validate signatures from the authorization server. This URL `MUST` use the `https` scheme. The JWK Set `MAY` also contain the server's encryption key or keys, which are used by clients to encrypt requests to the server. When both signing and encryption keys are made available, a `use` (public key use) parameter value is `REQUIRED` for all keys in the referenced JWK Set to indicate each key's intended usage.|[RFC 8414], [RFC 7517]|
|`grant_types_supported`|JSON array containing a list of the OAuth 2.0 grant type values that this authorization server supports. It `MUST` be set to `authorization_code`|[RFC 8414]|
|`response_types_supported`|JSON array containing a list of the OAuth 2.0 `response_type` values that this authorization server supports. It `MUST` be set to `code`|[RFC 8414]|
|`token_endpoint_auth_methods_supported`|JSON array containing a list of client authentication methods supported by this PAR and Token endpoint. It `MUST` be set to values `private_key_jwt`, `attest_jwt_client_auth`.|[RFC 8414], [RFC 9126], [RFC 7521], [OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth]|
|`pushed_authorization_request_endpoint`|The URL of the pushed authorization request endpoint at which a client can post an authorization request to exchange for a `request_uri` value usable at the authorization server.|[RFC 9126]|
|`require_pushed_authorization_requests`|Boolean parameter indicating whether the authorization server accepts authorization request data only via PAR. It `MUST` be set to `true`|[RFC 9126]|
|`dpop_signing_alg_values_supported`|A JSON array containing a list of the JWS alg values supported by the authorization server for DPoP proof JWTs. It `MUST` be set to values `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`|[RFC 7518], [RFC 9449]|
|`code_challenge_methods_supported`|JSON array containing a list of Proof Key for Code Exchange (PKCE) code challenge methods supported by this authorization server. It `MUST` be set to `S256`|[RFC 7636]|

The following is a non-normative example of Authorization Server Metadata, that requires authorization request to be
sent with PAR, defines authentication methods for Token/PAR endpoints, signals support for sender constrained access
tokens using DPoP and PKCE.

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorization",
  "token_endpoint": "https://as.example.com/token",
  "jwks_uri": "https://as.example.com/jwks",
  "response_types_supported": [
    "code"
  ],
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt",
    "attest_jwt_client_auth"
  ],
  "pushed_authorization_request_endpoint": "https://as.example.com/par",
  "require_pushed_authorization_requests": true,
  "dpop_signing_alg_values_supported": [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ]
}
```
