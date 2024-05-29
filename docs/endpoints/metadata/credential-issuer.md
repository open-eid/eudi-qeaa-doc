1. The Credential Issuer’s configuration `SHALL` be retrieved using the Credential Issuer Identifier.
2. Credential Issuers publishing metadata `MUST` make a JSON document available at the path formed by concatenating the
   string `/.well-known/openid-credential-issuer` to the `Credential Issuer Identifier`. If the Credential Issuer value
   contains a path component, any terminating / `MUST` be removed before
   appending `/.well-known/openid-credential-issuer`.
3. The path formed following the steps above `MUST` point to a JSON document compliant with [OPENID4VCI]) specification.
   The document `MUST` be returned using the `application/json` media type.

Credential Issuer Metadata Parameters are discussed in [OPENID4VCI] Sections 10.2 and E.2.2 for credentials complying
with [ISO/IEC 18013-5:2021]

<a id="vci-credential-issuer-metadata"></a>

|Claim|Description|Reference|
|:----|:----|:----|
|`authorization_servers`|Identifiers of the OAuth 2.0 Authorization Servers the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e., the Credential Issuer’s identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata|[OpenID4VCI], [RFC 8414]|
|`credential_issuer`|The Credential Issuer Identifier.|[OpenID4VCI]|
|`credential_endpoint`|URL of the Credential Endpoint. This URL `MUST` use the https scheme and `MAY` contain port, path, and query parameter components.|[OpenID4VCI]|
|`credential_nonce_endpoint`|URL of the Credential Nonce Endpoint. This URL `MUST` use the https scheme and `MAY` contain port, path, and query parameter components.|[OpenID4VCI]|
|`batch_credential_issuance`|Object containing information about the Credential Issuer's supports for batch issuance of Credentials on the Credential Endpoint. The presence of this parameter means that the issuer supports the proofs parameter in the Credential Request so can issue more than one Verifiable Credential for the same Credential Dataset in a single request/response. It must contain `batch_size` claim. Integer value specifying the maximum array size for the proofs parameter in a Credential Request.|[OpenID4VCI]|
|`credential_response_encryption`|Object containing information about whether the Credential Issuer supports encryption of the Credential Credential Response on top of TLS. It `MUST` defined as in [Credential Response Encryption Object](#vci-credential-response-encryption) table.|[OpenID4VCI]|
|`display`|An array of objects, where each object contains display properties of a Credential Issuer for a certain language. It `MUST` defined as in [Display Object](#vci-display-object).|[OpenID4VCI]|
|`credential_configurations_supported`|A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array `MUST` conform to the structure defined in OpenID4VCI, Section 10.2.3.1. and as defined in [Credentials Supported Object](#vci-credentials-supported-object) table.|[OpenID4VCI]|

<a id="vci-credential-response-encryption"></a>
**Credential Response Encryption Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`encryption_required`|Boolean value specifying whether the Credential Issuer requires the additional encryption on top of TLS for the Credential Response. If the value is true, the Credential Issuer requires encryption for every Credential Response and therefore the Wallet MUST provide encryption keys in the Credential Request. If the value is false, the Wallet MAY chose whether it provides encryption keys or not.|[OpenID4VCI]|
|`alg_values_supported`|Array containing a list of the JWE encryption algorithms (alg values) supported by the Credential Endpoint to encode the Credential Response in a JWT.|[OpenID4VCI], [RFC 7516], [RFC 7518], [RFC 7519]|
|`enc_values_supported`|Array containing a list of the JWE encryption algorithms (enc values) supported by the Credential Endpoint to encode the Credential Response in a JWT.|[OpenID4VCI], [RFC 7516], [RFC 7518], [RFC 7519]|

<a id="vci-display-object"></a>
**Display Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`name`|String value of a display name for the claim.|[OpenID4VCI]|
|`locale`|String value that identifies language of this object represented as language tag values defined in BCP47 [RFC 5646]. There MUST be only one object for each language identifier.|[OpenID4VCI], [RFC 5646]|

<a id="vci-credentials-supported-object"></a>
**Credentials Supported Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`format`|A JSON string identifying the format of this credential. It `MUST` be set to `mso_mdoc`.|[OpenID4VCI]|
|`doctype`| JSON string identifying the credential type as defined in ISO/IEC 18013-5:2021. It `MUST` be set to `org.iso.18013.5.1.mDL`.|[OpenID4VCI], [ISO/IEC 18013-5:2021]|
|`cryptographic_binding_methods_supported`|A JSON array containing a list of supported cryptographic binding methods. It `MUST` be set to `cose_key`.|[OpenID4VCI]|
|`proof_types_supported`|Object that describes specifics of the key proof(s) that the Credential Issuer supports. This object contains a list of name/value pairs, where each name is a unique identifier of the supported proof type(s). This identifier is also used by the Wallet in the [Credential Request](#vci-credential-request) as `proof_type` claim. It `MUST` contain `jwk` with JSON array `proof_signing_alg_values_supported` with supported algorithms as value.|[OpenID4VCI]|
|`display`|A JSON array containing a list of JSON objects, where each object contains the display properties of the supported credential for a certain language. It `MUST` defined as in [Credentials Supported Display Object](#vci-credentials-supported-display-object).|[OpenID4VCI]|
|`claims`|A JSON object containing a list of name/value pairs, where the name is a certain namespace as defined in ISO/IEC 18013-5:2021 (or any profile of it) and the value is a JSON object. It `MUST` defined as in [Credentials Supported Claims Object](#vci-credentials-supported-claims-object).|[OpenID4VCI]|

<a id="vci-credentials-supported-display-object"></a>
**Credentials Supported Display Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`name`|String value of a display name for the claim.|[OpenID4VCI]|
|`locale`|String value that identifies language of this object represented as language tag values defined in BCP47 [RFC 5646]. There MUST be only one object for each language identifier.|[OpenID4VCI], [RFC 5646]|
|`logo`|A JSON object with information about the logo of the Credential. It `MUST` defined as in [Logo Object](#vci-credentials-logo-object).|[OpenID4VCI]|
|`description`|String value of a description of the Credential.|[OpenID4VCI]|
|`background_color`|String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37.|[OpenID4VCI], [CSS-Color]|
|`text_color`|String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37|[OpenID4VCI], [CSS-Color]|

<a id="vci-credentials-logo-object"></a>
**Logo Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`url`|String value that contains a URI where the Wallet can obtain the logo of the Credential Issuer.|[OpenID4VCI]|
|`alt_text`|String value of the alternative text for the logo image.|[OpenID4VCI]|

<a id="vci-credentials-supported-claims-object"></a>
**Credentials Supported Claims Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`mandatory`|Boolean which when set to true indicates the claim MUST be present in the issued Credential. It `MUST` be set to `true` for all mandatory claims defined in ISO/IEC 18013-5:2021 |[OpenID4VCI], [ISO/IEC 18013-5:2021]|
|`display`|A JSON array containing a list of JSON objects, where each object contains display properties of a certain claim in the Credential for a certain language. It `MUST` defined as in [Display Object](#vci-display-object).|[OpenID4VCI]|

The following is a non-normative example of Credential Issuer Metadata with `org.iso.18013.5.1.mDL` as single supported
credential type and minimal set of mandatory claims as defined in [ISO/IEC 18013-5:2021].

```json
{
   "credential_issuer": "https://credential-issuer.example.com",
   "credential_endpoint": "https://credential-issuer.example.com/credential",
   "credential_nonce_endpoint": "https://credential-issuer.example.com/nonce",
   "batch_credential_issuance": {
      "batch_size": 50
   },
   "credential_configurations_supported": {
      "org.iso.18013.5.1.mDL": {
         "format": "mso_mdoc",
         "doctype": "org.iso.18013.5.1.mDL",
         "cryptographic_binding_methods_supported": [
            "cose_key"
         ],
         "credential_signing_alg_values_supported": [
            "ES256"
         ],
         "proof_types_supported": {
            "jwt": {
               "proof_signing_alg_values_supported": [
                  "RS256",
                  "RS384",
                  "RS512",
                  "ES256",
                  "ES384",
                  "ES512",
                  "PS256",
                  "PS384",
                  "PS512"
               ]
            }
         },
         "display": [
            {
               "name": "Mobile Driving License",
               "locale": "en",
               "logo": {
                  "uri": "https://eudi-issuer.example.com/credential_logo_en.png",
                  "alt_text": null
               },
               "description": "Description",
               "background_color": "#5F5",
               "text_color": "#282"
            }
         ],
         "claims": {
            "org.iso.18013.5.1": {
               "un_distinguishing_sign": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "UN distinguishing sign",
                        "locale": "en"
                     }
                  ]
               },
               "driving_privileges": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Driving privileges",
                        "locale": "en"
                     }
                  ]
               },
               "document_number": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Document number",
                        "locale": "en"
                     }
                  ]
               },
               "issue_date": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Issue date",
                        "locale": "en"
                     }
                  ]
               },
               "issuing_country": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Issuing country",
                        "locale": "en"
                     }
                  ]
               },
               "issuing_authority": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Issuing authority",
                        "locale": "en"
                     }
                  ]
               },
               "birth_date": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Birthdate",
                        "locale": "en"
                     }
                  ]
               },
               "expiry_date": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Expiry date",
                        "locale": "en"
                     }
                  ]
               },
               "given_name": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Given Name",
                        "locale": "en"
                     }
                  ]
               },
               "portrait": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Portrait",
                        "locale": "en"
                     }
                  ]
               },
               "family_name": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Family Name",
                        "locale": "en"
                     }
                  ]
               }
            }
         }
      }
   },
   "credential_response_encryption": {
      "required": false,
      "alg_values_supported": [
         "RSA-OAEP",
         "RSA-OAEP-256",
         "ECDH-ES",
         "ECDH-ES+A128KW",
         "ECDH-ES+A192KW",
         "ECDH-ES+A256KW"
      ],
      "enc_values_supported": [
         "A128GCM",
         "A192GCM",
         "A256GCM",
         "A128CBC-HS256",
         "A192CBC-HS384",
         "A256CBC-HS512"
      ]
   },
   "display": [
      {
         "name": "EUDI Credential issuer",
         "locale": "en"
      }
   ],
   "authorization_servers": [
      "https://as.example.com"
   ]
}
```
