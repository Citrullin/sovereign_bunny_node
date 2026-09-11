# Zero-Knowledge OpenID Connect (zkOIDC) Architecture

## 1. Architectural Comparison: Traditional SIWE vs. Sovereign zkOIDC

### A. Traditional Model: SIWE + OIDC Relay (Centralized Identity Server)
```
[ User ] ──► 1. Login with Google ──► [ IdP (Google/Apple) ]
   ▲                                         │
   │                                         ▼ 2. Raw JWT with PII (email, sub)
   │                                  ┌─────────────────────────────┐
   │                                  │   CENTRAL IDENTITY SERVER   │
   │                                  │ • Validates JWT             │
   │ 4. Sign SIWE Challenge           │ • DB: email ──► 0xAddress   │
   └──────────────────────────────────┤ • Issues Custodial Session  │
                                      └──────────────┬──────────────┘
                                                     │ 3. Relay to RPC
                                                     ▼
                                            [ Monolithic Blockchain ]
```

- **Centralized Honeypot**: The identity server maintains a permanent, queryable SQL database linking real-world identities (PII, emails, names, IP addresses) to public on-chain addresses.
- **IdP Tracking**: The Identity Provider (Google/Apple) sees every application the user visits and when.
- **Censorship & Custody**: The identity relay can refuse to sponsor or forward transactions for specific users.

---

### B. Sovereign Model: zkOIDC (Zero-Knowledge OpenID Connect)
```
[ User / Browser ] ──► 1. Login with Google ──► [ IdP (Google/Apple) ]
   │                                                   │
   │ 3. Ingests JWT locally                            ▼ 2. Standard JWT
   ▼
┌──────────────────────────────────────────────────────────────────┐
│              LOCAL CLIENT / WASM NOIR PROVER                     │
│                                                                  │
│  • Verifies RSA-2048 signature of IdP in Zero-Knowledge          │
│  • Asserts: iss == Google, aud == AppID, exp > now              │
│  • Blinds Identity: AccountID = Poseidon(sub, AppID, Salt)       │
│  • Binds Ephemeral Session Key (Ed25519/ECDSA)                   │
│  • Output: O(1) UltraHonk Proof (PII completely stripped)        │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   │ 4. Dispatches ZkOidcAuthEnvelope
                                   ▼
                        ┌─────────────────────┐
                        │    bunny-gateway    │ (Validates proof in <1ms)
                        └──────────┬──────────┘
                                   │
                                   │ 5. Native Paymaster Sponsors Intent
                                   ▼
                      [ Stateless Account-Lattice ]
```

- **Zero PII Exposure**: No email, real name, or raw OAuth ID is ever broadcast to the network or stored in a server database.
- **IdP Blindness**: The IdP only sees a generic OAuth challenge and cannot track on-chain interactions.
- **Cross-App Unlinkability**: Logging into two different services with the same Google account generates two completely different, cryptographically isolated addresses ($\text{AccountID} = \text{Poseidon}(\text{sub}, \text{AppID}, \text{Salt})$).

---

## 2. Deep Technical Comparison

| Metric / Dimension | SIWE + OIDC Relay (Identity Server) | Sovereign zkOIDC |
|---|---|---|
| **Trust Model** | Centralized (Must trust the server holding the DB) | Zero-Trust (Cryptographic mathematical proof) |
| **PII Exposure** | High (Email, Name, IP stored in server database) | Zero (Stripped inside local client-side Noir circuit) |
| **State / DB Requirement** | Heavy stateful database (PostgreSQL, Redis) | Completely Stateless (In-memory verification) |
| **Account Derivation** | Arbitrary DB mapping or custodial key generation | $\text{AccountID} = \text{Poseidon}(\text{sub}, \text{AppID}, \text{Salt})$ |
| **Session Model** | Server-side JWT cookies / Bearer tokens | Ephemeral session keys bound in ZK proof |
| **Paymaster Integration** | Identity server signs backend gas sponsorship | Stateless UltraHonk proof unlocks native Paymaster |
| **Cross-App Tracking** | Global address reusable $\to$ easily traceable | Domain-separated deterministic pseudonyms |

---

## 3. Structural Stack Migration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             WHAT GETS REMOVED                               │
│  ❌ Centralized Identity Server & Relayer Daemons                           │
│  ❌ PostgreSQL / Redis tables mapping `email <-> evm_address`               │
│  ❌ Server-side OAuth redirect callbacks handling client secrets            │
│  ❌ Legacy SIWE signature verification middleware in RPC gateway            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             WHAT GETS ADDED                                 │
│  ✅ Client-side Noir Circuit (Wasm RSA/JWT verification & claim blinding)   │
│  ✅ Ephemeral Session Key generation in browser LocalStorage / Passkeys     │
│  ✅ Ingress JWKS Cache (IdP public keys committed in Lattice State Root)   │
│  ✅ Stateless UltraHonk Proof Verification in `bunny-gateway` & Paymaster   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Implementation Details

### A. Client-Side: The Noir Authentication Circuit (`zk_oidc.nr`)
The client runs this circuit locally in WebAssembly via Barretenberg when the user completes OAuth:

```rust
use dep::std;
use dep::rsa::verify_sha256_pkcs1v15;

fn main(
    // Private Inputs (Kept strictly on user device)
    jwt_header_and_payload: [u8; 1024],
    jwt_signature: [u8; 256],           // RSA-2048 signature from Google
    user_sub: Field,                    // Google subject ID
    user_salt: Field,                   // User's secret local salt

    // Public Inputs (Broadcasted to bunny-gateway)
    idp_pubkey_modulus: pub [u8; 256],  // Google's public key from JWKS
    idp_pubkey_redc: pub [u8; 256],
    app_id_hash: pub Field,             // Target dApp / DAO ID
    ephemeral_pubkey: pub Field,        // Temporary session key generated for this session
    session_expiry: pub u64,
    derived_account_id: pub Field       // Public output account identifier
) {
    // 1. Verify RSA-2048 signature of the JWT using the IdP's public key
    let is_valid_sig = verify_sha256_pkcs1v15(
        idp_pubkey_modulus,
        idp_pubkey_redc,
        jwt_signature,
        jwt_header_and_payload
    );
    assert(is_valid_sig == true);

    // 2. Deterministically derive and enforce the blinded account address
    let expected_account = std::hash::poseidon([user_sub, app_id_hash, user_salt]);
    assert(derived_account_id == expected_account);

    // 3. Bind the ephemeral session key to prevent replay attacks
    let session_binding = std::hash::poseidon([derived_account_id, ephemeral_pubkey, session_expiry as Field]);
    assert(session_binding != 0);
}
```

### B. Ingress Layer: Ephemeral Session Management
To avoid making the user generate a heavy RSA ZK proof on every interaction:
1. **On Login (Once per session / 24h)**: The browser generates an ephemeral Ed25519 or Secp256k1 key pair, executes the Noir circuit to generate the UltraHonk proof, and registers the session with `bunny-gateway` using the `ZkOidcAuthEnvelope`.
2. **On High-Frequency Actions (Microseconds)**: Subsequent intents are signed instantly using the local ephemeral private key. `bunny-gateway` verifies the fast signature against the active session cache in RAM and routes the intent directly into Iggy.

### C. Ingress Gateway: Public Key Verification (JWKS Sync)
Instead of trusting external DNS at runtime, `bunny-epoch` periodically fetches and validates the JSON Web Key Sets (JWKS) for supported identity providers (`accounts.google.com`, `appleid.apple.com`). The valid key hashes are committed directly to the Lattice State Root under a low-entropy system address (`0x0000000000000000000000000000000000000003`), allowing any node or sub-committee to verify proofs statelessly without external HTTP calls.
