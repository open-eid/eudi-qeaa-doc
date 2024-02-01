1. The Credential Nonce Endpoint is an HTTP API at the QEAA Provider and `MUST` accept
   HTTP `POST` request with parameters in the HTTP request message body using the `application/x-www-form-urlencoded`
   format.
2. This endpoint is requested by Authorization Server as alternative flow to issue credential nonce that Credential
   Issuer can trust. Alternately the Authorization Server does not make credential nonce request and would not return it
   in Token Endpoint response and is instead acquired from Credential endpoint error response as described
   in [OpenID4VCI].

<a id="vci-credential-nonce-request"></a>
## Credential Nonce Request

|Parameter|Description|Reference|
|:----|:----|:----|
|`ath`|Hash of the `Access Token`.|[OpenID4VCI]|

<a id="vci-credential-nonce-response"></a>
## Credential Nonce Response

1. It `MUST` send `200 HTTP` status code on successful Credential Nonce Response.
2. Credential Nonce Response `MUST` be sent using `application/json` content type and contain following claims:
3. The `c_nonce` `SHALL` be linked to the `ath` request parameter for later validation in Credential Endpoint, where
   credential issuance is requested with sender constrained access token.

|Claim|Description|Reference|
|:----|:----|:----|
|`c_nonce`|JSON string containing a nonce value to be used to create a proof of possession of the key material when requesting a further credential or for the renewal of a credential.|[OpenID4VCI]|
|`c_nonce_expires_in`|Expiry time of the `c_nonce` in seconds.|[OpenID4VCI]|