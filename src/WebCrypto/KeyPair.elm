module WebCrypto.KeyPair exposing
    ( KeyPair, SerializedKeyPair, serializedKeyPairDecoder, encodeSerializedKeyPair
    , generateKeyPair, exportKeyPair, importKeyPair
    , publicKeyHash, deriveSharedKey
    )

{-| ECDH P-256 key exchange via WebCrypto.


# Types

@docs KeyPair, SerializedKeyPair, serializedKeyPairDecoder, encodeSerializedKeyPair


# Key Management

@docs generateKeyPair, exportKeyPair, importKeyPair


# Operations

@docs publicKeyHash, deriveSharedKey

-}

import ConcurrentTask exposing (ConcurrentTask)
import Json.Decode as Decode
import Json.Encode as Encode
import WebCrypto
import WebCrypto.Symmetric as Symmetric


{-| Opaque handle to an ECDH key pair.
Wraps the JWK-serialized keys and public key hash.
The actual `CryptoKey` objects are re-imported on the JS side for each operation.
-}
type KeyPair
    = KeyPair SerializedKeyPair


{-| Serialized key pair for storage. Both keys are JWK JSON strings.
-}
type alias SerializedKeyPair =
    { publicKey : String
    , privateKey : String
    , publicKeyHash : String
    }


{-| JSON decoder for a serialized key pair.
-}
serializedKeyPairDecoder : Decode.Decoder SerializedKeyPair
serializedKeyPairDecoder =
    Decode.map3 SerializedKeyPair
        (Decode.field "publicKey" Decode.string)
        (Decode.field "privateKey" Decode.string)
        (Decode.field "publicKeyHash" Decode.string)


{-| JSON encoder for a serialized key pair.
-}
encodeSerializedKeyPair : SerializedKeyPair -> Encode.Value
encodeSerializedKeyPair skp =
    Encode.object
        [ ( "publicKey", Encode.string skp.publicKey )
        , ( "privateKey", Encode.string skp.privateKey )
        , ( "publicKeyHash", Encode.string skp.publicKeyHash )
        ]


{-| Generate a new ECDH P-256 key pair.
Also computes the public key hash (SHA-256 of raw public key bytes).
-}
generateKeyPair : ConcurrentTask Never KeyPair
generateKeyPair =
    ConcurrentTask.define
        { function = "webcrypto:kp:generate"
        , expect = ConcurrentTask.expectJson (Decode.map KeyPair serializedKeyPairDecoder)
        , errors = ConcurrentTask.expectNoErrors
        , args = Encode.null
        }


{-| Export a key pair to JWK strings + public key hash.
-}
exportKeyPair : KeyPair -> SerializedKeyPair
exportKeyPair (KeyPair skp) =
    skp


{-| Import a key pair from JWK strings.
-}
importKeyPair : SerializedKeyPair -> KeyPair
importKeyPair =
    KeyPair


{-| Get the SHA-256 hash of the public key (hex string).
This is the user's identity in partage.
-}
publicKeyHash : KeyPair -> String
publicKeyHash (KeyPair skp) =
    skp.publicKeyHash


{-| Derive a shared AES-256-GCM key from my private key and another's public key.
Uses ECDH key agreement. The result can be used for symmetric encryption.
-}
deriveSharedKey :
    { myKeyPair : KeyPair, otherPublicKey : String }
    -> ConcurrentTask WebCrypto.Error Symmetric.Key
deriveSharedKey { myKeyPair, otherPublicKey } =
    let
        skp =
            exportKeyPair myKeyPair
    in
    ConcurrentTask.define
        { function = "webcrypto:kp:deriveSharedKey"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "myPrivateKeyJwk", Encode.string skp.privateKey )
                , ( "otherPublicKeyJwk", Encode.string otherPublicKey )
                ]
        }
        |> ConcurrentTask.map Symmetric.importKey
