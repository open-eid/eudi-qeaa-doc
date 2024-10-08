1. The Token Endpoint is an HTTP API at the Authorization Server and is used by the Wallet Instance to obtain an Access
   Token by presenting its authorization grant, as defined in [RFC 6749]
2. It `MUST` accept HTTP `POST` request with parameters in the HTTP request message body using
   the `application/x-www-form-urlencoded` format [OpenID4VCI].
3. It `MUST` use the `https` scheme.
4. It `MUST` issue sender-constrained Access Tokens [RFC 9449].
5. It `MUST` use `attest_jwt_client_auth` Client Authentication method as defined in [RFC 7523], [RFC 7521].

<a id="vci-token-request"></a>
### Token Request

|Parameter|Description|Reference|
|:----|:----|:----|
|`client_id`|It `MUST` be set to `sub` claim value of the [WIA](#wia-jwt).|[RFC 6749]|
|`grant_type`|It `MUST` be set to `authorization_code`.|[RFC 6749], [RFC 7521]|
|`code`|It `MUST` be set to Authorization code returned in the Authentication Response.|[RFC 6749], [RFC 7521]|
|`code_verifier`|Verification code of the `code_challenge` sent in PAR Request.|[RFC 7636]|
|`client_assertion_type`|It `MUST` be set to `urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation`.|[OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth]|
|`client_assertion`|It `MUST` contain two JWTs separated by a `~` character. It `MUST NOT` contain more or less than precisely two JWTs separated by the `~` character. The first JWT MUST be the [WIA](#wia-jwt) as `Client Attestation JWT` the second JWT `MUST` be the `Client Attestation PoP JWT` ([WIA-PoP](#vci-token-client-attestation-pop-jwt)) that `MUST` be signed by the private key defined in [WIA](#wia-jwt) `cnf` claim.|[OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth], Sections 4.1.1, 4.1.2|
|`redirect_uri`|It `MUST` be set as in the PAR Request Object.|[RFC 6749], [RFC 7521]|

<a id="vci-token-client-attestation-pop-jwt"></a>
**Client Attestation PoP JWT (WIA-PoP)*

**Header**

|Claim|Description|Reference|
|:----|:----|:----|
|`alg`|A digital signature algorithm identifier such as per IANA `JSON Web Signature and Encryption Algorithms`. It `MUST NOT` be set to `none` or any symmetric algorithm (MAC) identifier.|[RFC 7515] Section 4.1.1|
|`kid`|It `MUST` reference the thumbprint value of the `cnf` claim in [WIA](#wia-jwt).|[RFC 7638] Section 3, [attestation-based-client-auth]|
|`typ`|It `MUST` be set to `wallet-attestation-pop+jwt`. The `typ` claims in Client Attestation and Client Attestation PoP are still under discussion.|[attestation-based-client-auth]|

**Payload**

|Claim|Description|Reference|
|:----|:----|:----|
|`iss`|It `MUST` be set to `sub` claim value of the [WIA](#wia-jwt).|[attestation-based-client-auth]|
|`aud`|It `MUST` be set to the URL of Authorization Server Token Endpoint.|[attestation-based-client-auth]|
|`exp`|It `MUST` be UNIX Timestamp with the expiry time of the JWT.|[attestation-based-client-auth]|
|`jti`|Claim that provides a unique identifier for the token. The Authorization Server `MAY` ensure that JWTs are not replayed by maintaining the set of used `jti` values for the length of time for which the JWT would be considered valid based on the applicable `exp` instant.|[attestation-based-client-auth]|

<a id="vci-token-dpop-proof-jwt"></a>
**DPoP Proof JWT**

1. A `DPoP Proof` JWT `MUST` be included in an HTTP request using the `DPoP` header parameter containing a DPoP JWS.

**Header**

|Claim|Description|Reference|
|:----|:----|:----|
|`typ`|It `MUST` be set to `dpop+jwt`.|[RFC 7515], [RFC 9449]|
|`alg`|A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It `MUST NOT` be set to `none` or with a symmetric algorithm (MAC) identifier.|[RFC 7515]|
|`jwk`|Public key generated by the Wallet Instance, in JSON Web Key (JWK) [RFC 7517] format that the Access Token shall be bound to, as defined in Section 4.1.3 of [RFC 7515]. It `MUST NOT` contain a private key.|[RFC 7515], [RFC 7517]|

**Payload**

|Claim|Description|Reference|
|:----|:----|:----|
|`jti`|It `MUST` be set to a UUIDv4 value to uniquely identify the DPoP proof JWT.|[RFC 4122], [RFC 9449]|
|`htm`|The value of the HTTP method of the request to which the JWT is attached. It `MUST` be set to `POST`.|[RFC 9449]|
|`htu`|The HTTP target URI, without query and fragment parts, of the request to which the JWT is attached. It `MUST` be set to Token Endpoint URI.|[RFC 9449]|
|`iat`|It `MUST` be set to the time of the JWT issuance as a UNIX Timestamp.|[RFC 9449]|

<a id="vci-token-request-validation-steps"></a>
#### Validation Steps

1. It `MUST` use `attest_jwt_client_auth` Client Authentication method as defined
   in [OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth].
2. It `MUST` ensure that the Authorization `code` is issued to the authenticated Wallet Instance ([RFC 6749]).
3. It `MUST` ensure the Authorization `code` is valid and has not been previously used ([RFC 6749]).
4. It `MUST` ensure the `redirect_uri` is equals to the value that was initially included in
   the `Request Object` ([OpenID.Core], Section 3.1.3.1).
5. It `MUST` validate the DPoP Proof JWT following the steps in Section 4.3 of ([RFC 9449]). If the DPoP proof is
   invalid, the Token endpoint returns an error response, according to Section 5.2 of [RFC 6749]
   with `invalid_dpop_proof` as the value of the error parameter.
6. It `MUST` validate the Token Request as specified in [Token Request](#token-request) table.

### Token response

1. It `MUST` send `200 HTTP` status code on successful Token Response.
2. Token Response `MUST` be sent using `application/json` content type and contain following claims:

|Claim|Description|Reference|
|:----|:----|:----|
|`access_token`|The sender-constrained (DPoP) Access Token. Allows accessing the QEAA Provider Credential Endpoint to obtain the credential. It `MUST` be a signed JWT and contain claims as defined in [Access Token](#access-token) table.|[RFC 6749]|
|`token_type`|Type of Access Token returned. It `MUST` be set to `DPoP`.|[RFC 6749], [RFC 9449]|
|`c_nonce`|A nonce value to be used for proof of possession of key material in a subsequent request to the Credential Endpoint. When received, the Wallet `MUST` use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce.|[OpenID4VCI]|
|`c_nonce_expires_in`|Expiry time of the `c_nonce` in seconds.|[OpenID4VCI]|

<a id="vci-token-access-token"></a>
#### Access Token

1. A sender-constrained (DPoP) Access Token `MUST` be generated by the Token Endpoint as a result of a successful
   token request.
2. It `MUST` be encoded in JWT format, according to [RFC 7519].
3. It `MUST` be bound to the public key, that is provided by the `DPoP proof` as defined in Section 6 of [RFC 9449].
3. It `MUST` have at least the following mandatory claims:

**Header**

|Claim|Description|Reference|
|:----|:----|:----|
|`typ`|It `MUST` be set to `at+jwt`.|[RFC 9068]|

**Payload**

|Claim|Description|Reference|
|:----|:----|:----|
|`iss`|It `MUST` be an HTTPS URL that uniquely identifies the Authorization Server. The QEAA Provider `MUST` verify that this value matches the trusted Authorization Server.|[RFC 9068], [RFC 7519]|
|`sub`|It identifies the subject of the JWT. It `MUST` be set to the `personal_identification_number` claim value from `eu.europa.ec.eudi.pid.ee.1` domestic namespace of the [PID](#pid-attestation).|[RFC 9068], [OpenId.Core], [RFC 7519]|
|`client_id`|It `MUST` be set to `sub` claim value of the [WIA](#wia-jwt).|[RFC 9068]|
|`aud`|It `MUST` be set to the Credential Issuer Identifier.|[RFC 9068]|
|`iat`|It `MUST` be set to the time of the JWT issuance as a UNIX Timestamp|[RFC 9068], [RFC 7519]|
|`exp`|It `MUST` be set to the expiry time of the JWT as a UNIX Timestamp|[RFC 9068], [RFC 7519]|
|`cnf`|JSON object. It `MUST` contain single claim `jkt`. It uses `JWK SHA-256 Thumbprint Confirmation Method`. The value of the `jkt` member `MUST` be the base64url encoding of the JWK SHA-256 Thumbprint of the DPoP public key (in JWK format) to which the Access Token is bound.|[RFC 9449], [RFC 7638], [RFC 7515]|

<a id="vci-token-response-validation-steps"></a>
#### Validation Steps

1. The Wallet Instance `MUST` encrypt long-lived sender-constrained Access Token before storing it.
