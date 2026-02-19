# elm-webcrypto: WebCrypto API for Elm via elm-concurrent-task

## Purpose

An Elm package wrapping the browser's [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) as composable `ConcurrentTask` values. Covers symmetric encryption (AES-256-GCM), asymmetric key exchange (ECDH P-256), digital signatures (ECDSA), hashing (SHA-256), and Proof-of-Work computation. All cryptographic operations run in JavaScript via `crypto.subtle`; Elm handles composition, types, and error handling.

## Scope

**In scope (elm-concurrent-task based):**
- AES-256-GCM symmetric key generation, encryption, decryption
- Symmetric key export/import (raw bytes <-> Base64 string)
- ECDH P-256 key pair generation, export, import
- Shared secret derivation (ECDH key agreement)
- ECDSA P-256 key pair generation, export, import
- Digital signature creation and verification
- SHA-256 hashing
- Proof-of-Work solver (background Web Worker)
- Convenience wrappers: encryptString, decryptString, encryptJSON, decryptJSON
- Public key hashing (SHA-256 of exported key -> hex string for identity)

**Out of scope:**
- Other algorithms (RSA, AES-CBC, etc.) -- only what partage uses
- Key storage -- handled by elm-indexeddb
- Certificate management, TLS -- browser handles those

---

## Cryptographic Operations Reference (from partage)

### Configuration Constants

```
SYMMETRIC_ALGORITHM:  AES-GCM
SYMMETRIC_KEY_LENGTH: 256 bits
ASYMMETRIC_ALGORITHM: ECDH
ASYMMETRIC_CURVE:     P-256
SIGNATURE_ALGORITHM:  ECDSA
HASH_ALGORITHM:       SHA-256
```

### Symmetric Encryption (AES-256-GCM)

**Key generation:**
```
crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  extractable: true,
  usages: ["encrypt", "decrypt"]
)
```

**Encryption:**
```
iv = crypto.getRandomValues(new Uint8Array(12))  // 96-bit random IV
ciphertext = crypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  key,
  plaintext
)
Result: { ciphertext: Uint8Array, iv: Uint8Array }
```
AES-GCM appends a 128-bit authentication tag to the ciphertext automatically.

**Decryption:**
```
plaintext = crypto.subtle.decrypt(
  { name: "AES-GCM", iv: encrypted.iv },
  key,
  encrypted.ciphertext
)
```

**Key export (raw -> Base64):**
```
rawBytes = crypto.subtle.exportKey("raw", key)
base64 = btoa(String.fromCharCode(...new Uint8Array(rawBytes)))
```

**Key import (Base64 -> CryptoKey):**
```
keyData = Uint8Array.from(atob(base64), c => c.charCodeAt(0))
key = crypto.subtle.importKey(
  "raw", keyData,
  { name: "AES-GCM", length: 256 },
  extractable: true,
  usages: ["encrypt", "decrypt"]
)
```

### ECDH Key Pair (P-256)

**Key generation:**
```
keypair = crypto.subtle.generateKey(
  { name: "ECDH", namedCurve: "P-256" },
  extractable: true,
  usages: ["deriveKey"]
)
Result: { publicKey: CryptoKey, privateKey: CryptoKey }
```

**Key export (JWK format):**
```
publicJwk = crypto.subtle.exportKey("jwk", keypair.publicKey)
privateJwk = crypto.subtle.exportKey("jwk", keypair.privateKey)
// Serialized as JSON strings for storage
```

**Key import:**
```
publicKey = crypto.subtle.importKey(
  "jwk", jwkObj,
  { name: "ECDH", namedCurve: "P-256" },
  extractable: true,
  usages: []  // public keys have no usages for ECDH
)
privateKey = crypto.subtle.importKey(
  "jwk", jwkObj,
  { name: "ECDH", namedCurve: "P-256" },
  extractable: true,
  usages: ["deriveKey"]
)
```

**Public key hashing (identity):**
```
rawBytes = crypto.subtle.exportKey("raw", publicKey)
hashBuffer = crypto.subtle.digest("SHA-256", rawBytes)
hexString = Array.from(new Uint8Array(hashBuffer))
  .map(b => b.toString(16).padStart(2, "0"))
  .join("")
```

**Shared key derivation (ECDH key agreement):**
```
sharedKey = crypto.subtle.deriveKey(
  { name: "ECDH", public: otherPublicKey },
  myPrivateKey,
  { name: "AES-GCM", length: 256 },
  extractable: true,
  usages: ["encrypt", "decrypt"]
)
```

### ECDSA Digital Signatures (P-256)

**Key generation:**
```
signingKeypair = crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  extractable: true,
  usages: ["sign", "verify"]
)
```

**Signing:**
```
signature = crypto.subtle.sign(
  { name: "ECDSA", hash: "SHA-256" },
  privateKey,
  data  // Uint8Array
)
Result: ArrayBuffer (64 bytes for P-256)
```

**Verification:**
```
isValid = crypto.subtle.verify(
  { name: "ECDSA", hash: "SHA-256" },
  publicKey,
  signature,  // ArrayBuffer
  data        // Uint8Array
)
Result: boolean
```

**Key export/import:** Same JWK pattern as ECDH but with `{ name: "ECDSA", namedCurve: "P-256" }` and usages `["sign"]`/`["verify"]`.

### SHA-256 Hashing

```
hashBuffer = crypto.subtle.digest("SHA-256", data)  // data: Uint8Array
hexString = Array.from(new Uint8Array(hashBuffer))
  .map(b => b.toString(16).padStart(2, "0"))
  .join("")
```

### Password Derivation (SHA-256 -> Base64url)

Partage derives PocketBase passwords from group keys:

```
keyBytes = Uint8Array.from(atob(groupKeyBase64), c => c.charCodeAt(0))
hashBuffer = crypto.subtle.digest("SHA-256", keyBytes)
hashArray = new Uint8Array(hashBuffer)
base64 = btoa(String.fromCharCode(...hashArray))
base64url = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
```

### Proof-of-Work (SHA-256 brute force)

**Algorithm:**
1. Receive `{ challenge, difficulty }` from server
2. Start with `nonce = 0`
3. Compute `SHA-256(challenge + nonceString)`
4. Check if hash has `difficulty` leading zero bits:
   - Check `Math.floor(difficulty / 4)` full hex chars are `"0"`
   - Check next hex char is `< 2^(4 - (difficulty % 4))`
5. If not, increment nonce and repeat
6. Return the nonce string that satisfies the difficulty

**Performance:** Difficulty 18 requires ~2^18 = 262,144 attempts on average, taking ~2-4 seconds.

**Web Worker:** The PoW solver runs in a Web Worker to avoid blocking the UI thread. The worker receives `{ challenge, difficulty }` and posts back `{ nonce, hashesComputed }`.

---

## Elm API Design

### Module: `WebCrypto`

Top-level re-exports and common types.

```elm
module WebCrypto exposing
    ( Error(..)
    , sha256
    , sha256Hex
    )
```

#### Types

```elm
type Error
    = EncryptionFailed String
    | DecryptionFailed String
    | KeyGenerationFailed String
    | KeyImportFailed String
    | KeyExportFailed String
    | SigningFailed String
    | VerificationFailed String
    | HashingFailed String
    | InvalidKey String
```

#### Functions

```elm
{-| Compute SHA-256 hash of raw bytes. Returns hex string. -}
sha256Hex : List Int -> ConcurrentTask Error String


{-| Compute SHA-256 hash of a string. Returns hex string. -}
sha256 : String -> ConcurrentTask Error String
```

### Module: `WebCrypto.Symmetric`

AES-256-GCM symmetric encryption.

```elm
module WebCrypto.Symmetric exposing
    ( Key
    , EncryptedData
    , generateKey
    , encrypt, decrypt
    , encryptString, decryptString
    , encryptJson, decryptJson
    , exportKey, importKey
    )
```

#### Types

```elm
{-| Opaque handle to an AES-256-GCM key stored in JS.
Cannot be inspected from Elm -- only used as a parameter to crypto operations.
-}
type Key
    = Key String  -- wraps a key ID


{-| Encrypted data: ciphertext + initialization vector.
Both are represented as Base64 strings for safe JSON serialization.
-}
type alias EncryptedData =
    { ciphertext : String  -- Base64
    , iv : String          -- Base64
    }
```

#### Functions

```elm
{-| Generate a new random AES-256-GCM key. -}
generateKey : ConcurrentTask Never Key


{-| Encrypt raw bytes with AES-256-GCM.
Generates a random 96-bit IV. Returns ciphertext (with appended auth tag) and IV.
-}
encrypt : Key -> List Int -> ConcurrentTask Error EncryptedData


{-| Decrypt data encrypted with AES-256-GCM.
Verifies the authentication tag. Fails if key is wrong or data is corrupted.
-}
decrypt : Key -> EncryptedData -> ConcurrentTask Error (List Int)


{-| Encrypt a string. Encodes to UTF-8 before encryption. -}
encryptString : Key -> String -> ConcurrentTask Error EncryptedData


{-| Decrypt to a string. Decodes UTF-8 after decryption. -}
decryptString : Key -> EncryptedData -> ConcurrentTask Error String


{-| Encrypt a JSON value. Serializes to JSON string, then encrypts. -}
encryptJson : Key -> Encode.Value -> ConcurrentTask Error EncryptedData


{-| Decrypt a JSON value. Decrypts, then parses JSON.
Uses the provided decoder to produce a typed value.
-}
decryptJson : Key -> Decode.Decoder a -> EncryptedData -> ConcurrentTask Error a


{-| Export a key to a Base64 string for storage (e.g. in IndexedDB). -}
exportKey : Key -> ConcurrentTask Error String


{-| Import a key from a Base64 string. -}
importKey : String -> ConcurrentTask Error Key
```

### Module: `WebCrypto.KeyPair`

ECDH P-256 key exchange.

```elm
module WebCrypto.KeyPair exposing
    ( KeyPair
    , SerializedKeyPair
    , generateKeyPair
    , exportKeyPair, importKeyPair
    , publicKeyHash
    , deriveSharedKey
    , importPublicKey
    )
```

#### Types

```elm
{-| Opaque handle to an ECDH key pair stored in JS. -}
type KeyPair
    = KeyPair String  -- wraps a keypair ID


{-| Serialized key pair for storage. Both keys are JWK JSON strings. -}
type alias SerializedKeyPair =
    { publicKey : String       -- JWK JSON
    , privateKey : String      -- JWK JSON
    , publicKeyHash : String   -- SHA-256 hex hash (identity)
    }
```

#### Functions

```elm
{-| Generate a new ECDH P-256 key pair.
Also computes the public key hash (SHA-256 of raw public key bytes).
-}
generateKeyPair : ConcurrentTask Never KeyPair


{-| Export a key pair to JWK strings + public key hash. -}
exportKeyPair : KeyPair -> ConcurrentTask Error SerializedKeyPair


{-| Import a key pair from JWK strings. -}
importKeyPair : SerializedKeyPair -> ConcurrentTask Error KeyPair


{-| Compute the SHA-256 hash of a public key (hex string).
This is the user's identity in partage.
-}
publicKeyHash : KeyPair -> ConcurrentTask Error String


{-| Derive a shared AES-256-GCM key from my private key and another's public key.
Uses ECDH key agreement. The result can be used for symmetric encryption.
-}
deriveSharedKey :
    { myKeyPair : KeyPair, otherPublicKey : String }
    -> ConcurrentTask Error Symmetric.Key


{-| Import a public key from a JWK string (for verification or key agreement). -}
importPublicKey : String -> ConcurrentTask Error KeyPair
```

### Module: `WebCrypto.Signature`

ECDSA P-256 digital signatures.

```elm
module WebCrypto.Signature exposing
    ( SigningKeyPair
    , SerializedSigningKeyPair
    , generateSigningKeyPair
    , exportSigningKeyPair, importSigningKeyPair
    , sign, verify
    )
```

#### Types

```elm
{-| Opaque handle to an ECDSA signing key pair stored in JS. -}
type SigningKeyPair
    = SigningKeyPair String


{-| Serialized signing key pair for storage. -}
type alias SerializedSigningKeyPair =
    { publicKey : String   -- JWK JSON
    , privateKey : String  -- JWK JSON
    }
```

#### Functions

```elm
{-| Generate a new ECDSA P-256 key pair for signing/verification. -}
generateSigningKeyPair : ConcurrentTask Never SigningKeyPair


{-| Export a signing key pair to JWK strings. -}
exportSigningKeyPair : SigningKeyPair -> ConcurrentTask Error SerializedSigningKeyPair


{-| Import a signing key pair from JWK strings. -}
importSigningKeyPair : SerializedSigningKeyPair -> ConcurrentTask Error SigningKeyPair


{-| Sign data with the private key. Returns the signature as a Base64 string. -}
sign : SigningKeyPair -> List Int -> ConcurrentTask Error String


{-| Verify a signature against data and a public key (JWK string).
Returns True if the signature is valid.
-}
verify : String -> String -> List Int -> ConcurrentTask Error Bool
```

### Module: `WebCrypto.ProofOfWork`

SHA-256 Proof-of-Work solver.

```elm
module WebCrypto.ProofOfWork exposing
    ( Challenge
    , Solution
    , solveChallenge
    )
```

#### Types

```elm
type alias Challenge =
    { challenge : String
    , timestamp : Int
    , difficulty : Int
    , signature : String
    }


type alias Solution =
    { pow_challenge : String
    , pow_timestamp : Int
    , pow_difficulty : Int
    , pow_signature : String
    , pow_solution : String  -- the nonce
    }
```

#### Functions

```elm
{-| Solve a Proof-of-Work challenge.
Runs SHA-256 brute force in a Web Worker to avoid blocking the UI.
Finds a nonce such that SHA-256(challenge + nonce) has `difficulty` leading zero bits.
For difficulty 18, this takes ~2-4 seconds.
-}
solveChallenge : Challenge -> ConcurrentTask Error Solution
```

---

## JS Companion Design

```javascript
// js/src/index.js

export function createTasks() {
  const keys = new Map();         // keyId -> CryptoKey
  const keypairs = new Map();     // keypairId -> { publicKey, privateKey }
  const signingKeypairs = new Map();
  let nextId = 0;

  function newId() { return String(nextId++); }

  function storeKey(key) {
    const id = newId();
    keys.set(id, key);
    return id;
  }

  function getKey(id) {
    const key = keys.get(id);
    if (!key) return { error: "INVALID_KEY:Key not found" };
    return key;
  }

  function storeKeypair(kp) {
    const id = newId();
    keypairs.set(id, kp);
    return id;
  }

  // --- Helpers ---

  function toBase64(uint8array) {
    return btoa(String.fromCharCode(...uint8array));
  }

  function fromBase64(base64) {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  async function rawPublicKeyHash(publicKey) {
    const rawBytes = await crypto.subtle.exportKey("raw", publicKey);
    const hashBuffer = await crypto.subtle.digest("SHA-256", rawBytes);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  return {
    // --- SHA-256 ---

    "webcrypto:sha256hex": async ({ data }) => {
      try {
        const bytes = typeof data === "string"
          ? new TextEncoder().encode(data)
          : new Uint8Array(data);
        const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
        return Array.from(new Uint8Array(hashBuffer))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      } catch (e) {
        return { error: "HASHING_FAILED:" + e.message };
      }
    },

    // --- Symmetric (AES-256-GCM) ---

    "webcrypto:sym:generateKey": async () => {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      return storeKey(key);
    },

    "webcrypto:sym:encrypt": async ({ keyId, data }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plaintext = new Uint8Array(data);
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          plaintext
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decrypt": async ({ keyId, ciphertext, iv }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          key,
          fromBase64(ciphertext)
        );
        return Array.from(new Uint8Array(decrypted));
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    "webcrypto:sym:encryptString": async ({ keyId, plaintext }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(plaintext);
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          data
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decryptString": async ({ keyId, ciphertext, iv }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          key,
          fromBase64(ciphertext)
        );
        return new TextDecoder().decode(decrypted);
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    "webcrypto:sym:encryptJson": async ({ keyId, json }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(JSON.stringify(json));
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          data
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decryptJson": async ({ keyId, ciphertext, iv }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          key,
          fromBase64(ciphertext)
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    "webcrypto:sym:exportKey": async ({ keyId }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const exported = await crypto.subtle.exportKey("raw", key);
        return toBase64(new Uint8Array(exported));
      } catch (e) {
        return { error: "KEY_EXPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:importKey": async ({ base64 }) => {
      try {
        const keyData = fromBase64(base64);
        const key = await crypto.subtle.importKey(
          "raw",
          keyData,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );
        return storeKey(key);
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    // --- Key Pair (ECDH P-256) ---

    "webcrypto:kp:generate": async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"]
      );
      return storeKeypair(kp);
    },

    "webcrypto:kp:export": async ({ keypairId }) => {
      const kp = keypairs.get(keypairId);
      if (!kp) return { error: "INVALID_KEY:KeyPair not found" };
      try {
        const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
        const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        const hash = await rawPublicKeyHash(kp.publicKey);
        return {
          publicKey: JSON.stringify(pubJwk),
          privateKey: JSON.stringify(privJwk),
          publicKeyHash: hash,
        };
      } catch (e) {
        return { error: "KEY_EXPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:kp:import": async ({ publicKey, privateKey }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKey),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          []
        );
        const privKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(privateKey),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey"]
        );
        return storeKeypair({ publicKey: pubKey, privateKey: privKey });
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:kp:publicKeyHash": async ({ keypairId }) => {
      const kp = keypairs.get(keypairId);
      if (!kp) return { error: "INVALID_KEY:KeyPair not found" };
      return await rawPublicKeyHash(kp.publicKey);
    },

    "webcrypto:kp:deriveSharedKey": async ({ myKeypairId, otherPublicKeyJwk }) => {
      const kp = keypairs.get(myKeypairId);
      if (!kp) return { error: "INVALID_KEY:KeyPair not found" };
      try {
        const otherPub = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(otherPublicKeyJwk),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          []
        );
        const sharedKey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: otherPub },
          kp.privateKey,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );
        return storeKey(sharedKey);
      } catch (e) {
        return { error: "KEY_DERIVATION_FAILED:" + e.message };
      }
    },

    // --- Signing (ECDSA P-256) ---

    "webcrypto:sig:generate": async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const id = newId();
      signingKeypairs.set(id, kp);
      return id;
    },

    "webcrypto:sig:export": async ({ sigKeypairId }) => {
      const kp = signingKeypairs.get(sigKeypairId);
      if (!kp) return { error: "INVALID_KEY:SigningKeyPair not found" };
      try {
        const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
        const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        return {
          publicKey: JSON.stringify(pubJwk),
          privateKey: JSON.stringify(privJwk),
        };
      } catch (e) {
        return { error: "KEY_EXPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:import": async ({ publicKey, privateKey }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKey),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"]
        );
        const privKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(privateKey),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign"]
        );
        const id = newId();
        signingKeypairs.set(id, { publicKey: pubKey, privateKey: privKey });
        return id;
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:sign": async ({ sigKeypairId, data }) => {
      const kp = signingKeypairs.get(sigKeypairId);
      if (!kp) return { error: "INVALID_KEY:SigningKeyPair not found" };
      try {
        const signature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          kp.privateKey,
          new Uint8Array(data)
        );
        return toBase64(new Uint8Array(signature));
      } catch (e) {
        return { error: "SIGNING_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:verify": async ({ publicKeyJwk, signature, data }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKeyJwk),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"]
        );
        return await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          pubKey,
          fromBase64(signature),
          new Uint8Array(data)
        );
      } catch (e) {
        return { error: "VERIFICATION_FAILED:" + e.message };
      }
    },

    // --- Proof of Work ---

    "webcrypto:pow:solve": ({ challenge, difficulty }) => {
      return new Promise((resolve) => {
        // Create inline Web Worker to avoid blocking UI
        const workerCode = `
          async function solve(challenge, difficulty) {
            const encoder = new TextEncoder();
            let nonce = 0;
            while (true) {
              const input = challenge + String(nonce);
              const hashBuffer = await crypto.subtle.digest(
                "SHA-256",
                encoder.encode(input)
              );
              const hashArray = new Uint8Array(hashBuffer);
              if (checkDifficulty(hashArray, difficulty)) {
                return String(nonce);
              }
              nonce++;
            }
          }

          function checkDifficulty(hashBytes, difficulty) {
            const fullBytes = Math.floor(difficulty / 8);
            const remainingBits = difficulty % 8;
            for (let i = 0; i < fullBytes; i++) {
              if (hashBytes[i] !== 0) return false;
            }
            if (remainingBits > 0) {
              const mask = 0xFF << (8 - remainingBits);
              if ((hashBytes[fullBytes] & mask) !== 0) return false;
            }
            return true;
          }

          self.onmessage = async (e) => {
            const { challenge, difficulty } = e.data;
            const nonce = await solve(challenge, difficulty);
            self.postMessage({ nonce });
          };
        `;
        const blob = new Blob([workerCode], { type: "application/javascript" });
        const worker = new Worker(URL.createObjectURL(blob));
        worker.onmessage = (e) => {
          worker.terminate();
          resolve(e.data.nonce);
        };
        worker.postMessage({ challenge, difficulty });
      });
    },
  };
}
```

---

## Error Protocol

### Wire Format

| JS returns | Elm sees |
|---|---|
| `"abc123"` / `{ ciphertext, iv }` | `Success value` |
| `{ error: "DECRYPTION_FAILED:Invalid key or corrupted data" }` | `Error (DecryptionFailed "Invalid key or corrupted data")` |
| `{ error: "INVALID_KEY:Key not found" }` | `Error (InvalidKey "Key not found")` |
| `{ error: "KEY_IMPORT_FAILED:..." }` | `Error (KeyImportFailed "...")` |
| thrown exception | `UnexpectedError (UnhandledJsException ...)` |

### Elm Error Decoder

```elm
errorDecoder : Decode.Decoder Error
errorDecoder =
    Decode.string
        |> Decode.andThen
            (\err ->
                case splitOnce ":" err of
                    Just ( "ENCRYPTION_FAILED", msg ) -> Decode.succeed (EncryptionFailed msg)
                    Just ( "DECRYPTION_FAILED", msg ) -> Decode.succeed (DecryptionFailed msg)
                    Just ( "KEY_GENERATION_FAILED", msg ) -> Decode.succeed (KeyGenerationFailed msg)
                    Just ( "KEY_IMPORT_FAILED", msg ) -> Decode.succeed (KeyImportFailed msg)
                    Just ( "KEY_EXPORT_FAILED", msg ) -> Decode.succeed (KeyExportFailed msg)
                    Just ( "KEY_DERIVATION_FAILED", msg ) -> Decode.succeed (InvalidKey msg)
                    Just ( "SIGNING_FAILED", msg ) -> Decode.succeed (SigningFailed msg)
                    Just ( "VERIFICATION_FAILED", msg ) -> Decode.succeed (VerificationFailed msg)
                    Just ( "HASHING_FAILED", msg ) -> Decode.succeed (HashingFailed msg)
                    Just ( "INVALID_KEY", msg ) -> Decode.succeed (InvalidKey msg)
                    _ -> Decode.fail ("Unknown WebCrypto error: " ++ err)
            )
```

---

## Usage Example: Partage Identity Initialization

```elm
import ConcurrentTask exposing (ConcurrentTask)
import WebCrypto.KeyPair as KeyPair
import WebCrypto.Signature as Signature


type alias Identity =
    { keypair : KeyPair.SerializedKeyPair
    , signingKeypair : Signature.SerializedSigningKeyPair
    }


{-| Generate a new user identity (ECDH + ECDSA key pairs).
Returns serialized keys ready for storage in IndexedDB.
-}
initializeIdentity : ConcurrentTask WebCrypto.Error Identity
initializeIdentity =
    ConcurrentTask.map2 Identity
        -- Both key generations run concurrently
        (KeyPair.generateKeyPair
            |> ConcurrentTask.andThen KeyPair.exportKeyPair
        )
        (Signature.generateSigningKeyPair
            |> ConcurrentTask.andThen Signature.exportSigningKeyPair
        )
```

## Usage Example: Encrypting an Entry Payload

```elm
import WebCrypto.Symmetric as Symmetric


type alias ExpensePayload =
    { description : String
    , amount : Float
    , currency : String
    , date : String
    , payers : List { memberId : String, amount : Float }
    , beneficiaries : List { memberId : String, shares : Int }
    }


{-| Encrypt an expense payload for storage in Loro.
The result is a JSON string containing { ciphertext, iv } in Base64.
-}
encryptExpense :
    Symmetric.Key
    -> ExpensePayload
    -> ConcurrentTask WebCrypto.Error String
encryptExpense key payload =
    Symmetric.encryptJson key (encodeExpensePayload payload)
        |> ConcurrentTask.map
            (\encrypted ->
                Encode.encode 0
                    (Encode.object
                        [ ( "ciphertext", Encode.string encrypted.ciphertext )
                        , ( "iv", Encode.string encrypted.iv )
                        ]
                    )
            )
```

## Usage Example: Proof-of-Work Group Creation

```elm
import WebCrypto.ProofOfWork as PoW
import PocketBase
import PocketBase.Custom


{-| Full group creation flow:
1. Fetch PoW challenge from server
2. Solve PoW in background Web Worker
3. Create group with PoW solution
-}
createGroupWithPoW :
    PocketBase.Client
    -> { createdBy : String }
    -> ConcurrentTask Error GroupRecord
createGroupWithPoW client { createdBy } =
    -- Step 1: Fetch PoW challenge
    PocketBase.Custom.fetch client
        { method = "GET"
        , path = "/api/pow/challenge"
        , body = Nothing
        , decoder = powChallengeDecoder
        }
        |> ConcurrentTask.mapError PocketBaseError
        -- Step 2: Solve PoW (runs in Web Worker, ~2-4 seconds)
        |> ConcurrentTask.andThen
            (\challenge ->
                PoW.solveChallenge challenge
                    |> ConcurrentTask.mapError CryptoError
            )
        -- Step 3: Create group with solution
        |> ConcurrentTask.andThen
            (\solution ->
                PocketBase.Custom.fetch client
                    { method = "POST"
                    , path = "/api/collections/groups/records"
                    , body = Just (encodeGroupCreation createdBy solution)
                    , decoder = groupRecordDecoder
                    }
                    |> ConcurrentTask.mapError PocketBaseError
            )
```

---

## Key Design Decisions

1. **Opaque key handles, not raw bytes.** `Key`, `KeyPair`, and `SigningKeyPair` are opaque types wrapping string IDs. The actual `CryptoKey` objects live in JS memory and are never serialized through ports. This is both more secure (keys don't traverse the Elm/JS boundary) and more efficient (no re-import on every operation).

2. **Base64 for encrypted data.** `EncryptedData` uses Base64 strings rather than `List Int` for ciphertext and IV. This matches partage's existing storage format (the `encryptedPayload` field in Loro maps) and avoids large JSON arrays for encrypted blobs.

3. **PoW runs in a Web Worker.** The `solveChallenge` task creates an inline Web Worker, runs the SHA-256 brute force loop there, and resolves the Promise when a solution is found. From Elm's perspective, it's just a long-running task.

4. **Error types are flat.** Rather than a deeply nested error hierarchy, each error variant carries a descriptive string message. This keeps pattern matching simple and avoids over-engineering for a security-critical module where errors are typically fatal.

5. **JSON round-trip for JWK keys.** ECDH and ECDSA keys are exported as JWK JSON strings. This is the most portable format and matches what partage stores in IndexedDB. The Elm side treats them as opaque strings; the JS side `JSON.parse`/`JSON.stringify` as needed.

6. **No key rotation in the library.** Key rotation (tracking `keyVersion`, trying multiple keys) is application-level logic, not a crypto primitive. The library provides `importKey` and the app decides which key to try.
