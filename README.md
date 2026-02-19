# elm-webcrypto

WebCrypto API for Elm via [elm-concurrent-task](https://package.elm-lang.org/packages/andrewMacmurray/elm-concurrent-task/latest/).

Wraps the browser's [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) as composable `ConcurrentTask` values. All cryptographic operations run in JavaScript via `crypto.subtle`; Elm handles composition, types, and error handling.

## Capabilities

- **Symmetric encryption** -- AES-256-GCM key generation, encryption, decryption, key export/import
- **Key exchange** -- ECDH P-256 key pair generation, shared secret derivation
- **Digital signatures** -- ECDSA P-256 signing and verification
- **Hashing** -- SHA-256
- **Proof-of-Work** -- SHA-256 brute force solver (runs in a Web Worker)

## Modules

| Module                  | Purpose                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `WebCrypto`             | `Error` type, `errorDecoder`, `sha256`, `sha256Hex`                                                                                        |
| `WebCrypto.Symmetric`   | AES-256-GCM: `generateKey`, `encrypt`, `decrypt`, `encryptString`, `decryptString`, `encryptJson`, `decryptJson`, `exportKey`, `importKey` |
| `WebCrypto.KeyPair`     | ECDH P-256: `generateKeyPair`, `exportKeyPair`, `importKeyPair`, `publicKeyHash`, `deriveSharedKey`                                        |
| `WebCrypto.Signature`   | ECDSA P-256: `generateSigningKeyPair`, `exportSigningKeyPair`, `importSigningKeyPair`, `sign`, `verify`                                    |
| `WebCrypto.ProofOfWork` | `solveChallenge`                                                                                                                           |

## Setup

This package requires both an Elm dependency and a JS companion.

### 1. Elm dependency

Add `mpizenberg/elm-webcrypto` to your `elm.json` dependencies.

### 2. JS companion

Register the WebCrypto task runners with your `elm-concurrent-task` runner:

```javascript
import { createTasks } from "elm-webcrypto";

// When setting up your ConcurrentTask runner:
const runner = ConcurrentTask.createRunner({
  tasks: {
    ...createTasks(),
    // ... your other tasks
  },
});
```

## Usage

Each crypto operation is a `ConcurrentTask` that can be chained and composed:

```elm
import ConcurrentTask exposing (ConcurrentTask)
import WebCrypto
import WebCrypto.Symmetric as Symmetric


encryptMessage : Symmetric.Key -> String -> ConcurrentTask WebCrypto.Error Symmetric.EncryptedData
encryptMessage key message =
    Symmetric.encryptString key message
```

### Generate an identity (ECDH + ECDSA key pairs)

```elm
import WebCrypto.KeyPair as KeyPair
import WebCrypto.Signature as Signature


type alias Identity =
    { keypair : KeyPair.SerializedKeyPair
    , signingKeypair : Signature.SerializedSigningKeyPair
    }


initializeIdentity : ConcurrentTask Never Identity
initializeIdentity =
    ConcurrentTask.map2 Identity
        (KeyPair.generateKeyPair
            |> ConcurrentTask.map KeyPair.exportKeyPair
        )
        (Signature.generateSigningKeyPair
            |> ConcurrentTask.map Signature.exportSigningKeyPair
        )
```

### Encrypt and decrypt JSON

```elm
encryptPayload : Symmetric.Key -> Encode.Value -> ConcurrentTask WebCrypto.Error Symmetric.EncryptedData
encryptPayload key value =
    Symmetric.encryptJson key value


decryptPayload : Symmetric.Key -> Decode.Decoder a -> Symmetric.EncryptedData -> ConcurrentTask WebCrypto.Error a
decryptPayload key decoder encrypted =
    Symmetric.decryptJson key decoder encrypted
```

### Derive a shared key (ECDH)

```elm
deriveAndEncrypt : KeyPair.KeyPair -> String -> String -> ConcurrentTask WebCrypto.Error Symmetric.EncryptedData
deriveAndEncrypt myKeyPair otherPublicKeyJwk message =
    KeyPair.deriveSharedKey
        { myKeyPair = myKeyPair, otherPublicKey = otherPublicKeyJwk }
        |> ConcurrentTask.andThen
            (\sharedKey -> Symmetric.encryptString sharedKey message)
```

## Design

**Elm-owned keys, stateless JS.** `Key`, `KeyPair`, and `SigningKeyPair` are opaque types holding serialized key material (Base64 or JWK). There is no JS-side state -- keys are re-imported into `CryptoKey` objects on each operation. This means `exportKey`/`importKey`, `exportKeyPair`/`importKeyPair`, `exportSigningKeyPair`/`importSigningKeyPair`, and `publicKeyHash` are all pure Elm functions.

**Pure Elm where possible.** String/JSON encryption and decryption, UTF-8 encoding, key serialization, and all JSON codecs are pure Elm -- only the raw crypto operations (generate, encrypt, decrypt, sign, verify, hash, PoW) call into JS.

**Flat error type.** All operations share a single `WebCrypto.Error` type. Errors carry a descriptive message from the JS side.
