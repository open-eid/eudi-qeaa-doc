1. The Credential Endpoint is an HTTP API at the QEAA Provider and `MUST` accept HTTP `POST` using
   the `application/json` media type.
2. It `MUST` issue a Credential as approved by the End-User upon presentation of a valid `Access Token`, representing
   this approval, as defined in [OPENID4VCI].
3. It `MUST` accept only sender-constrained `Access Tokens`.
4. It `MUST` issue Credentials that are cryptographically bound to the identifier of the End-User who possesses the
   Credential (Wallet Instance).
5. It `MUST` use the `immediate` Credential Response type.
6. It `MUST` use `c_nonce` and `c_nonce_expires_in` to support Credential updates.
7. It `MUST` use DPoP Authentication Scheme ([RFC 9449]) by accepting the sender-constrained access
   token in the `Authorization` header and the `DPoP proof JWT` in the `DPoP` header.
8. It `MUST` support `jwt Key Proof` as described in [OPENID4VCI].

<a id="vci-credential-request"></a>
### Credential Request

1. The Wallet Instance `MUST` create a new `DPoP proof` for the Credential Endpoint and bind it to access token
   using `ath` claim. It `MUST` be included in an HTTP request using the `DPoP` header parameter as described
   in [RFC 9449].
2. It `MUST` include sender-constrained Access Token in `Authorization` header as described in [RFC 9449].
3. It `MUST` use the following parameters in the entity-body of the HTTP `POST` request, using the `application/json`
   media type:

|Claim|Description|Reference|
|:----|:----|:----|
|`credential_identifier`|A string that identifies a Credential Dataset that is requested for issuance. It `MUST` be one of the values published in [Credential Issuer metadata](#vci-credential-issuer-metadata) `credential_configurations_supported` claim.  `REQUIRED` when access token `authorization_details` claim contains `credential_configuration_id` claim. It `MUST NOT` be used otherwise. When this parameter is used, the `format` and `doctype` parameters `MUST NOT` be present. |[OPENID4VCI]|
|`format`|Format of the Credential to be issued. It `MUST` be set to `mso_mdoc` as published in Credential Issuer Metadata. `REQUIRED` when access token `authorization_details` claim contains `format` claim. It `MUST NOT` be used otherwise. It `MUST NOT` be used if `credential_identifier` parameter is present. |[OPENID4VCI]|
|`doctype`|JSON string identifying the credential type as defined in [ISO/IEC 18013-5:2021]. `REQUIRED` when the format parameter is present. It `MUST NOT` be used otherwise. It `MUST` be set to `org.iso.18013.5.1.mDL`. |[OPENID4VCI], Section E.2.5|
|`proof`|JSON object containing proof of possession of the key material the issued credential shall be bound to. It `MUST NOT` be used if `proofs` parameter is present. The proof object `MUST` contain the mandatory claims as defined in [Credential Request Proof Object](#vci-credential-request-proof-object) table. |[OPENID4VCI]|
|`proofs`|JSON array containing proof of possession objects. It `MUST NOT` be used if `proof` parameter is present. If `proofs` parameter is set, the credential endpoint `MUST` return one credential per provided `proof` in its `credentials` response parameter.|[OPENID4VCI]|
|`credential_response_encryption`|Object containing information for encrypting the Credential Response. If this request element is not present, the corresponding credential response returned is not encrypted. It `MUST` defined as in [Credential Response Encryption Object](#vci-credential-response-encryption) table.|[OPENID4VCI]|

<a id="vci-credentials-request-claims-object"></a>
**Credential Request Claims Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`org.iso.18013.5.1`|A JSON object containing a list of name/value pairs, where the name is a claim name value that is defined in the respective namespace and is offered in the Credential.|[OpenID4VCI]|

<a id="vci-credentials-request-proof-object"></a>
**Credential Request Proof Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`proof_type`| JSON string denoting the proof type. It `MUST` be set to `jwt`.|[OPENID4VCI]|
|`jwt`|The JWT used as proof of possession. It `MUST` be signed by the private key defined in WIA `cnf` claim. It `MUST` contain JWT as defined in [jwt Key Proof](#vci-jwt-key-proof) |[OPENID4VCI]|

<a id="vci-jwt-key-proof"></a>
**jwt Key Proof**

The `jwt Key Proof` type `MUST` contain following header/payload claims:

<a id="vci-credential-response-encryption"></a>
**Credential Response Encryption Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`jwk`|Object containing a single public key as a JWK used for encrypting the Credential Response.|[OpenID4VCI]|
|`alg`|JWE alg algorithm for encrypting Credential Responses.|[OpenID4VCI], [RFC7516], [RFC7518]|
|`enc`|JWE enc algorithm for encrypting Credential Responses.|[OpenID4VCI], [RFC7516], [RFC7518]|

**Header**

|Claim|Description|Reference|
|:----|:----|:----|
|`alg`|A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It `MUST NOT` be set to `none` or with a symmetric algorithm (MAC) identifier.|[OPENID4VCI], [RFC 7515], [RFC 7517]|
|`typ`|It `MUST` be set to `openid4vci-proof+jwt`|[OPENID4VCI], [RFC 7515], [RFC 7517]|
|`jwk`|It `MUST` contain the key material the new Credential shall be bound to.|[OPENID4VCI], [RFC 7515], [RFC 7517]|

**Payload**

|Claim|Description|Reference|
|:----|:----|:----|
|`iss`|It `MUST` be set to `sub` claim value of the [WIA](#wia-jwt).|[OPENID4VCI], [RFC 7517]|
|`aud`|It `MUST` be set to the identifier of the QEAA Provider.|[OPENID4VCI]|
|`iat`|It `MUST` be set to the time of the JWT issuance as a UNIX Timestamp|[OPENID4VCI], [RFC 7519]|
|`nonce`|It `MUST` be set to the `c_nonce` value returned by the Token Endpoint.|[OPENID4VCI]|

<a id="vci-dpop-proof-jwt"></a>
**DPoP proof JWT**

In addition to the values that are defined in the Token Endpoint, the proof `MUST` contain following claim:

|Claim|Description|Reference|
|:----|:----|:----|
|`ath`|Hash of the `Access Token`. The value `MUST` be the result of a base64url encoding (as defined in Section 2 of [RFC 7515]) the SHA-256 hash of the ASCII encoding of the associated `Access Token` value.|[RFC 9449], [RFC 7515]|

<a id="vci-credential-request-validation-steps"></a>
#### Validation Steps

1. The Credential Endpoint `MUST` validate the `DPoP proof` sent in the `DPoP` Header as defined in [RFC 9449] Section
   4.3. If the `DPoP proof` is invalid, the Credential Endpoint `MUST` return an error response
   with `invalid_dpop_proof` as the value of the `error` parameter.
2. If request to this endpoint is made without `DPoP proof JWT` or the `Access Token` is not sender-constrained the
   server `MUST` return `401 HTTP` response status with `WWW-Authenticate` header as defined in [RFC 9449], Section 7.1
3. It must `MUST` validate the sender-constrained access token from `Authorization` header.
4. It must `MUST` validate the [Credential Request](#vci-credential-request) parameters and return errors as described in [OPENID4VCI], Section 7.3.1.
5. It must `MUST` validate the `jwt Key Proof` as described in [OPENID4VCI], Section 7.2.2.
6. It must `MUST` validate the sender-constrained access token `authorization_details` claim.

<a id="vci-credential-response"></a>
### Credential Response

1. Credential Response can be `immediate` or `deferred`. This document `SHALL` implement `immediate` response.
2. It `MUST` send `201 HTTP` status code on successful Credential Response.
3. On failed Credential Response it `MUST` use error codes as described in [OPENID4VCI], Section 7.3.1.
4. If the Client requested an encrypted response by including the `credential_response_encryption` object in the request,
   the Credential Issuer `MUST` encode the information in the Credential Response as a JWT using the parameters from the
   `credential_response_encryption` object. If the Credential Response is encrypted, the media type of the response `MUST`
   be set to `application/jwt` and `application/json` otherwise. If encryption was requested in the Credential Request and the Credential Response is not
   encrypted, the Client `SHOULD` reject the Credential Response. 
5. Credential Response `MUST` contain following claims:

|Parameter|Description|Reference|
|:----|:----|:----|
|`credential`|Contains the issued Credentials. It `MUST NOT` be used if `credentials` parameter is present. It `MUST` be base64url-encoded JSON string in [ISO/IEC 18013-5:2021] format. It `MUST` contain CBOR encoded mDL as described in [MDOC-CBOR Format](#mdoc-cbor-format) section.|[OPENID4VCI], Appendix E|
|`credentials`|Contains array of issued Credentials. It `MUST NOT` be used if `credential` is present. Each element `MUST` be base64url-encoded JSON string in [ISO/IEC 18013-5:2021] format. Each `MUST` contain CBOR encoded mDL as described in [MDOC-CBOR Format](#mdoc-cbor-format) section. If `proofs` request parameter is set, the credential endpoint `MUST` return one credential per provided `proof` in its `credentials` response parameter.|[OPENID4VCI], Appendix E|
|`c_nonce`|JSON string containing a nonce value to be used to create a proof of possession of the key material when requesting a further credential or for the renewal of a credential.|[OPENID4VCI]|
|`c_nonce_expires_in`|JSON integer corresponding to the `c_nonce` lifetime in seconds.|[OPENID4VCI]|

<a id="vci-credential-response-validation-steps"></a>
#### Validation Steps

1. Wallet Instance `MUST` check that the response contains all the mandatory parameters and values are validated
   according to [Credential Response](#vci-credential-response)
2. It `MUST` validate that the QEAA Provider is not revoked before the issued credential issuing time.
3. It `MUST` validate that the Issued Credential is signed by corresponding QEAA Provider.
4. It `MUST` store `c_nonce`, `c_nonce_expires_in` claims to perform credential update in the future.
5. It `MUST` perform credential update before `c_nonce_expires_in`.
