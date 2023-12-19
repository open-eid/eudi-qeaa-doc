1. The Pushed Authorization Request Endpoint (PAR) Endpoint is an HTTP API at the Authorization Server and `MUST` accept
   HTTP `POST` request with parameters in the HTTP request message body using the `application/x-www-form-urlencoded`
   format.
2. It `MUST` use the `https` scheme.
3. Use of Pushed Authorization Requests (PAR) is `RECOMMENDED` by [OPENID4VCI].
4. It `MUST` use `attest_jwt_client_auth` Client Authentication method as defined
   in [OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth].
5. It `MUST` use the `request` parameter (`Request Object`) as defined in [RFC 9126] Section 3.
6. It `MUST` use the `authorization_details` parameter, as defined in [RFC 9396] and as `REQUIRED` by [OpenID4VCI].
7. The Authorization Server `MUST` be able to uniquely identify the Credential Issuer based on the `locations` claim
   value in `authorization_details` object as suggested by [OpenID4VCI].

### PAR Request

<a id="vci-par-request-parameters"></a>
**PAR Request Parameters**

|Parameter|Description|Reference|
|:----|:----|:----|
|`request`|It `MUST` be a signed JWT. It `MUST` be signed by the private key defined in [WIA](#wia-jwt) `cnf` claim. All request parameters `MUST` appear as claims of the JWT representing the authorization request except `client_assertion` and `client_assertion_type`.|[RFC 9126] Section 3|
|`client_assertion_type`|It `MUST` be set to `urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation`.|[OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth]|
|`client_assertion`|It `MUST` contain two JWTs separated by a `~` character. It `MUST NOT` contain more or less than precisely two JWTs separated by the `~` character. The first JWT MUST be the [WIA](#wia-jwt) as `Client Attestation JWT` the second JWT `MUST` be the `Client Attestation PoP JWT` ([WIA-PoP](#vci-par-client-attestation-pop-jwt)) that `MUST` be signed by the private key defined in [WIA](#wia-jwt) `cnf` claim.|[OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth], Sections 4.1.1, 4.1.2|

<a id="vci-par-client-attestation-pop-jwt"></a>
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
|`aud`|It `MUST` be set to the URL of Authorization Server PAR Endpoint.|[attestation-based-client-auth]|
|`exp`|It `MUST` be UNIX Timestamp with the expiry time of the JWT.|[attestation-based-client-auth]|
|`jti`|Claim that provides a unique identifier for the token. The Authorization Server `MAY` ensure that JWTs are not replayed by maintaining the set of used `jti` values for the length of time for which the JWT would be considered valid based on the applicable `exp` instant.|[attestation-based-client-auth]|

<a id="vci-par-request-object"></a>
**PAR Request Object**

**Header**

|Claim|Description|Reference|
|:----|:----|:----|
|`alg`|A digital signature algorithm identifier such as per IANA `JSON Web Signature and Encryption Algorithms`. It `MUST NOT` be set to `none` or any symmetric algorithm (MAC) identifier.|[RFC 7515] Section 4.1.1|
|`kid`|It `MUST` reference the thumbprint value of the `cnf` claim in [WIA](#wia-jwt).|[RFC 7638] Section 3|

**Payload**

|Claim|Description|Reference|
|:----|:----|:----|
|`iss`|It `MUST` be set to `sub` claim value of the [WIA](#wia-jwt).|[RFC 9126], [RFC 9101], [RFC 7519]|
|`aud`|It `MUST` be set to the URL of Authorization Server PAR Endpoint. |[RFC 9101], [RFC 7519]|
|`exp`|It `MUST` be UNIX Timestamp with the expiry time of the JWT.|[RFC 7519]|
|`iat`|It `MUST` be UNIX Timestamp with the time of JWT issuance.|[RFC 7519]|
|`jti`|Claim that provides a unique identifier for the token. The Authorization Server `MAY` ensure that JWTs are not replayed by maintaining the set of used `jti` values for the length of time for which the JWT would be considered valid based on the applicable `exp` instant.|[RFC 9126], [RFC 7519]|
|`state`|Unique session identifier at the client side. This value will be returned to the client in the response, at the end of the authentication. It `MUST` be a random string composed by alphanumeric characters and with a minimum length of 32 digits.|[OpenID.Core] Section 3.1.2.1, [RFC6749]|
|`code_challenge`|A challenge derived from the `code verifier` that is sent in the authorization request.|[RFC 7636] Section 4.2|
|`code_challenge_method`|A method that was used to derive `code challenge`. It `MUST` be set as `S256`.|[RFC 7636] Section 4.3|
|`client_id`|It `MUST` be set to `sub` claim value of the [WIA](#wia-jwt).|[RFC 9126], [RFC 6749], [RFC 7638]|
|`authorization_details`|A JSON array containing a list of [Authorization Details Object](#vci-authorization-details-object) used to convey details about the credentials the wallet wants to obtain.|[RFC 9396], [OpenID4VCI]|
|`response_type`|It `MUST` be set to `code`.|[RFC 6749]|
|`redirect_uri`|Redirection URI to which the response is intended to be sent. It `MUST` be an Universal (iOS) or App Link (Android) registered with the local operating system.|[RFC 6749]|

<a id="vci-authorization-details-object"></a>
**Authorization Details Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`type`|It `MUST` be set to `openid_credential`|[RFC 9396], [OpenID4VCI]|
|`format`|It `MUST` be set to `mso_doc`|[RFC 9396], [OpenID4VCI]|
|`locations`|If the Credential Issuer metadata contains an `authorization_server` parameter the `locations` field `MUST` be set to the Credential Issuer Identifier value. The value `MUST` be used as `aud` claim in Access Token returned by Token Endpoint. |[RFC 9396], [OpenID4VCI]|
|`doctype`|JSON string identifying the credential type. It `MUST` be set to `org.iso.18013.5.1.mDL` as defined in ISO/IEC 18013-5:2021 |[RFC 9396], [OpenID4VCI], [ISO/IEC 18013-5:2021]|
|`claims`|A JSON object containing a list of name/value pairs, where the name is a certain namespace as defined in ISO/IEC 18013-5:2021 (or any profile of it) and the value is a JSON object. It `MUST` defined as in [Authorization Details Claims Object](#vci-authorization-details-claims-object).|[RFC 9396], [OpenID4VCI], [ISO/IEC 18013-5:2021]|

<a id="vci-authorization-claims-object"></a>
**Authorization Details Claims Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`org.iso.18013.5.1`|A JSON object containing a list of name/value pairs, where the name is a claim name value that is defined in the respective namespace and is offered in the Credential.|[OpenID4VCI]|

<a id="vci-par-validation-steps"></a>
#### Validation Steps

1. Authorization Server `MUST` authenticate the Wallet Instance based on the `attest_jwt_client_auth` Client
   Authentication
   method ([OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth]).
2. All request parameters `MUST` appear as claims of the JWT representing the authorization request
   except `client_assertion` and `client_assertion_type` as required in [RFC 9126] Section 3.
2. It `MUST` validate the signature of the `Request Object` using the algorithm specified in the `alg` header
   parameter ([RFC 9126], [RFC 9101]) and the public key that can be retrieved from the [WIA](#wia-jwt) `cnf` claim using
   the `kid` header claim of the `Request Object`.
3. It `MUST` check that the used algorithm for signing the request in the `alg` header claim is among the appropriate
   cryptographic algorithms defined in [RFC 7515].
4. It `MUST` check that the `iss` claim in the `Request Object` matches the `client_id` claim in
   the `Request Object` ([RFC 9126], [RFC 9101]).
5. It `MUST` check that the `iss` and `client_id` claims are equal to the `sub` claim value in the Client Attestation
   JWT ([WIA](#wia-jwt)).
6. It `MUST` check that the `aud` claim in the `Request Object` is equal to the Authorization Server PAR Endpoint URI.
7. It `MUST` reject the PAR request, if `Request Object` contains the `request_uri` claim ([RFC 9126]).
8. It `MUST` check that the `Request Object` is not expired by checking the `exp` claim ([RFC 9126]).
9. It `MUST` check that the `Request Object` was issued at a time acceptable by the QEAA Provider by checking
   the `iat` claim ([RFC 9126]).
10. It `MUST` validate the `authorization_details` object.
11. It `MUST` check that the `jti` claim in the `Request Object` has not been used before by the Wallet Instance
    identified by the `client_id`. This allows the QEAA Provider to mitigate replay attacks ([RFC 7519]).
12. It `MUST` check the revocation status of the Wallet Provider, Wallet Instance and QEAA Provider.
13. It `MUST` validate that QEAA Provider is allowed to issue the credential type specified in claims `doctype`
    and `claims`.

### PAR Response

1. QEAA Provider `MUST` issue the `request_uri` for one-time use and bind it to the client identifier `client_id`.
2. It `MUST` send `201 HTTP` status code on successful PAR Response.
3. PAR Response `MUST` be sent using `application/json` content type and contain following claims:

|Claim|Description|Reference|
|:----|:----|:----|
|`request_uri`|The request URI corresponding to the authorization request posted. This URI `MUST` be a single-use reference to the respective authorization request. It `MUST` contain some part generated using a cryptographically strong pseudorandom algorithm such that it is computationally infeasible to predict or guess a valid value. The value format `MUST` be urn:ietf:params:oauth:request_uri:&lt;reference-value&gt; with &lt;reference-value&gt; as the random part of the URI that references the respective authorization request data. The request_uri value `MUST` be bound to the client that posted the authorization request. |[RFC 9126]|
|`expires_in`|JSON number that represents the lifetime of the request URI in seconds as a positive integer. It `SHOULD NOT` exceed 60 seconds.|[RFC 9126]|
