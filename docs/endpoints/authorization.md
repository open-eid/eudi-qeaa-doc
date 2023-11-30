1. The Authorization Endpoint is an HTTP API at the Authorization Server and used in the same manner as defined
   in [RFC 6749] to interact with the QEAA Provider and obtain an authorization grant.
2. Client `MUST` use Pushed Authorization Requests (PAR) [RFC 9126] to send the Authorization Request.

### Authorization Request

|Parameter|Description|Reference|
|:----|:----|:----|
|`client_id`|It `MUST` be set to `sub` claim value of the [Wallet Instance Attestation](#wia-jwt).|[RFC 9126]|
|`request_uri`|It `MUST` be set to the same value as obtained by PAR Response.|[RFC 9126]|

<a id="authorization-request-validation-steps"></a>
#### Validation Steps

1. It `MUST` treat `request_uri` values as one-time use and `MUST` reject an expired request.
2. It `MUST` identify the request as a result of the submitted PAR.
3. It `MUST` reject all the Authorization Requests that do not contain the `request_uri` parameter as the PAR is the
   only way to pass the Authorization Request from the Wallet Instance.
4. The Authorization Server `MUST` verify the identity of the User that owns the credential. It `MUST` initiate user
   authentication as described in `PID Authentication Flow`.

### Authorization response

|Parameter|Description|Reference|
|:----|:----|:----|
|`code`|Unique Authorization Code that the Wallet Instance submits to the Token Endpoint.|[RFC 6749]|
|`state`|It `MUST` be set to `state` value, that was used in `Request Object`|[RFC 6749]|

<a id="authorization-response-validation-steps"></a>
#### Validation Steps

1. It `MUST` check the returned `state` value is equal to the value sent by Wallet Instance in the `Request Object`.
2. It `MUST` check that the URL of Authorization Server in `iss` parameter is equal to the URL identifier of intended
   Authorization Server that the Wallet Instance started the authorization flow with.
