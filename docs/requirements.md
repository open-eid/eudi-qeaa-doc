### EUDI-ARF Requirements

[EUDI Architecture and Reference Framework][EUDI-ARF] Sections 5 and 6 specify the requirements for PID and (Q)EAA
Providers and EUDI Wallet Solution implementers.

### EUDI-ARF Implementation Scope

1. Only QEAA Provider related requirements `SHALL` be considered.
2. Only Mobile Driving Licence (mDL) use case `SHALL` be considered.
3. Only Type 1 configuration requirements `SHALL` be considered.
4. Only [ISO/IEC 18013-5:2021] data model `SHALL` be considered, due to EC Regulation 2023_127 (4th Driving License
   Regulation). This affects [EUDI-ARF] Section 5.2.1 requirements
   6,7,9 and 10 and Section 6.5.3 Attestation exchange Protocol - 7, Data model -2, PID & (Q)EAA formats -
   1 and Signature formats -1 requirements.
5. Only same-device issuing ([OPENID4VCI]) and presentation ([OPENID4VP]) flows `SHALL` be considered.
6. Pseudonymous authentication ([SIOPv2]) `SHALL NOT` be considered in [OpenID4VP] attestation exchange protocol. This
   affects [EUDI-ARF] Section 6.5.3 Attestation exchange Protocol - 1 requirement.
7. Trusted List mechanism to publish and obtain information about authoritative parties, e.g. Issuers of PID, (Q)EAA and
   Relying Parties as defined in [EUDI-ARF] Section 6.2 `SHALL NOT` be considered[^1].
8. Relying Party `MUST` be authenticated to Wallet Instance in [OPENID4VP] presentation flow[^1].
9. Wallet Instance `SHALL NOT` be required to authenticate to Relying Party in [OPENID4VP] presentation flow[^1].
10. The User `SHALL` have a valid Wallet Instance Attestation stored in a Wallet Instance[^1].
11. The User `SHALL` have a valid Person Identification Data Attestation stored in a Wallet Instance[^1].
12. The Authorization Server and Credential Issuer `SHALL` be considered as separate entities in [OPENID4VCI] protocol
    implementation.
13. The authorization response in [OPENID4VP] flow `SHALL NOT` be encrypted.
14. The issued Mobile Driving Licence `SHALL` have 7 day expiry time.
15. The Mobile Driving Licence issuer `SHALL NOT` provide revocation list.

[^1]: Implementation details are still under discussion within the EUDI Wallet ecosystem.
