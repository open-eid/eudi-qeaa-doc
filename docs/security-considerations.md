[OpenID4VCI] Section 11 outlines the various aspects of security issues in credential issuance, including
trust establishment between Wallet and Issuer, credential offer endpoint issues, pre-authorized code flow security,
credential lifecycle management recommendations, key proof replay prevention, and TLS requirements.

[OpenID4VP] Section 12 discusses various security considerations for the verifiable presentations protocol. It discusses
preventing replay of the VP Token, various security issues when direct_post is used, issues with user authentication
using verifiable credentials, issues related to [DIF.PresentationExchange] and following TLS best practices.

[OpenID4VC High Assurance Interoperability Profile with SD-JWT VC][draft-oid4vc-haip-sd-jwt-vc] aims to select features
and define a set of requirements for the existing specifications to enable interoperability among Issuers, Wallets and
Verifiers of Credentials where a high level of security and privacy is required.

[Security and Trust in OpenID for Verifiable Credentials][openid-4-vc-security-and-trust] describes the trust
architecture in OpenID for Verifiable Credentials (VCs), outlines security considerations and requirements for the
components in an ecosystem, and provides an informal security analysis of the OpenID 4 VC protocols.

[OAuth 2.0 Threat Model and Security Considerations][RFC 6819] gives additional security considerations for OAuth,
beyond those in the OAuth 2.0 specification, based on a comprehensive threat model for the OAuth 2.0 protocol.

[OAuth 2.0 Security Best Current Practice][I-D.ietf-oauth-security-topics] describes the best current security practice
for OAuth 2.0. It updates and extends the [OAuth 2.0 Security Threat Model][RFC 6819] to incorporate practical
experiences gathered since OAuth 2.0 was published and covers new threats relevant due to the broader application of
OAuth 2.0.

[OAuth 2.0 for Native Apps][RFC 8252] suggests that OAuth 2.0 authorization requests from native apps should only be
made through external user-agents, primarily the user's browser. It discusses the details the security and usability
reasons why this is the case and how native apps and authorization servers can implement this best practice. It also
recommends using domain-bound iOS Universal Link/Android App links for invoking native applications and are recommended
by this specification also.
