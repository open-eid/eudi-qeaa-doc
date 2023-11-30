The Wallet Instance Attestation (WIA) attests the authenticity and trustworthiness of a specific Wallet Instance. It may
contain details about the Wallet Provider, the Wallet Solution, the Wallet Instance, and the device's security level
where the Wallet Instance is installed. WIA implementation details are still under discussion within the EUDI Wallet
ecosystem.

<a id="wia-requirements"></a>
### Requirements

1. The User `SHALL` have a valid WIA stored in a Wallet Instance.

To support [OAuth 2.0 Attestation-Based Client Authentication][attestation-based-client-auth] in QEAA issuing and
PID presentation flows the following non-normative example of the Wallet Instance Attestation JWT is used:

<a id="wia-jwt"></a>
### Wallet Attestation JWT

**Header**

```json
{
  "typ": "wallet-attestation+jwt",
  "alg": "ES256",
  "kid": "wallet-provider-kid"
}
```

**Payload**

```json
{
  "iss": "https://wallet-provider.example.com",
  "sub": "https://wallet-provider.example.com",
  "iat": 1541493724,
  "exp": 1516247022,
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
      "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    }
  }
}
```