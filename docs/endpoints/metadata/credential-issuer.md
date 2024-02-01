1. The Credential Issuer’s configuration `SHALL` be retrieved using the Credential Issuer Identifier.
2. Credential Issuers publishing metadata `MUST` make a JSON document available at the path formed by concatenating the
   string `/.well-known/openid-credential-issuer` to the `Credential Issuer Identifier`. If the Credential Issuer value
   contains a path component, any terminating / `MUST` be removed before
   appending `/.well-known/openid-credential-issuer`.
3. The path formed following the steps above `MUST` point to a JSON document compliant with [OPENID4VCI]) specification.
   The document `MUST` be returned using the `application/json` media type.

Credential Issuer Metadata Parameters are discussed in [OPENID4VCI] Sections 10.2 and E.2.2 for credentials complying
with [ISO/IEC 18013-5:2021]

|Claim|Description|Reference|
|:----|:----|:----|
|`credential_issuer`|The Credential Issuer Identifier.|[OpenID4VCI]|
|`authorization_servers`|Identifiers of the OAuth 2.0 Authorization Servers the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e., the Credential Issuer’s identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata|[OpenID4VCI], [RFC 8414]|
|`credential_endpoint`|URL of the Credential Endpoint. This URL `MUST` use the https scheme and `MAY` contain port, path, and query parameter components.|[OpenID4VCI]|
|`credential_nonce_endpoint`|URL of the Credential Nonce Endpoint. This URL `MUST` use the https scheme and `MAY` contain port, path, and query parameter components.|[OpenID4VCI]|
|`display`|An array of objects, where each object contains display properties of a Credential Issuer for a certain language. It `MUST` defined as in [Display Object](#vci-display-object).|[OpenID4VCI]|
|`credential_configurations_supported`|A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array `MUST` conform to the structure defined in OpenID4VCI, Section 10.2.3.1. and as defined in [Credentials Supported Object](#vci-credentials-supported-object)|[OpenID4VCI]|

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
|`cryptographic_binding_methods_supported`|A JSON array containing a list of supported cryptographic binding methods. It `MUST` be set to `mso`.|[OpenID4VCI]|
|`proof_types_supported`|A JSON array of case sensitive strings, each representing `proof_type` that the Credential Issuer supports. It `MUST` be set to `jwk`.|[OpenID4VCI]|
|`display`|A JSON array containing a list of JSON objects, where each object contains the display properties of the supported credential for a certain language. It `MUST` defined as in [Credentials Supported Display Object](#vci-credentials-supported-display-object).|[OpenID4VCI]|
|`claims`|A JSON object containing a list of name/value pairs, where the name is a certain namespace as defined in ISO/IEC 18013-5:2021 (or any profile of it) and the value is a JSON object. It `MUST` defined as in [Credentials Supported Claims Object](#vci-credentials-supported-claims-object).|[OpenID4VCI]|

<a id="vci-credentials-supported-display-object"></a>
**Credentials Supported Display Object**

|Claim|Description|Reference|
|:----|:----|:----|
|`name`|String value of a display name for the claim.|[OpenID4VCI]|
|`locale`|String value that identifies language of this object represented as language tag values defined in BCP47 [RFC 5646]. There MUST be only one object for each language identifier.|[OpenID4VCI], [RFC 5646]|
|`logo`|A JSON object with information about the logo of the Credential.|[OpenID4VCI]|
|`description`|String value of a description of the Credential.|[OpenID4VCI]|
|`background_color`|String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37.|[OpenID4VCI], [CSS-Color]|
|`text_color`|String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37|[OpenID4VCI], [CSS-Color]|

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
   "authorization_servers": [
      "https://as.example.com"
   ],
   "credential_endpoint": "https://credential-issuer.example.com/credential",
   "display": [
      {
         "name": "Transpordiamet",
         "locale": "et-EE"
      },
      {
         "name": "Transport Administration",
         "locale": "en-US"
      }
   ],
   "credentials_supported": {
      "org.iso.18013.5.1.mDL": {
         "format": "mso_mdoc",
         "doctype": "org.iso.18013.5.1.mDL",
         "cryptographic_binding_methods_supported": [
            "mso"
         ],
         "proof_types_supported": [
            "jwt"
         ],
         "display": [
            {
               "name": "Mobiilne juhiluba",
               "locale": "et-EE",
               "logo": {
                  "url": "https://examplestate.com/public/mdl.png",
                  "alt_text": "mobiilse juhiloa kandiline kujund"
               },
               "background_color": "#12107c",
               "text_color": "#FFFFFF"
            },
            {
               "name": "Mobile Driving License",
               "locale": "en-US",
               "logo": {
                  "url": "https://examplestate.com/public/mdl.png",
                  "alt_text": "a square figure of a mobile driving licence"
               },
               "background_color": "#12107c",
               "text_color": "#FFFFFF"
            }
         ],
         "claims": {
            "org.iso.18013.5.1": {
               "given_name": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Eesnimi",
                        "locale": "et-EE"
                     },
                     {
                        "name": "Given Name",
                        "locale": "en-US"
                     }
                  ]
               },
               "family_name": {
                  "mandatory": true,
                  "display": [
                     {
                        "name": "Perekonnanimi",
                        "locale": "et-EE"
                     },
                     {
                        "name": "Surname",
                        "locale": "en-US"
                     }
                  ]
               },
               "birth_date": {
                  "mandatory": true
               },
               "issue_date": {
                  "mandatory": true
               },
               "expiry_date": {
                  "mandatory": true
               },
               "issuing_country": {
                  "mandatory": true
               },
               "issuing_authority": {
                  "mandatory": true
               },
               "document_number": {
                  "mandatory": true
               },
               "portrait": {
                  "mandatory": true
               },
               "driving_privileges": {
                  "mandatory": true
               }
            }
         }
      }
   }
}
```
