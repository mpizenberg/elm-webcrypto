module WebCrypto.KeyPair exposing
    ( KeyPair, SerializedKeyPair, serializedKeyPairDecoder, encodeSerializedKeyPair
    , generateKeyPair, exportKeyPair, importKeyPair, importPublicKey
    , publicKeyHash, deriveSharedKey
    )

{-| ECDH P-256 key exchange via WebCrypto.


# Types

@docs KeyPair, SerializedKeyPair, serializedKeyPairDecoder, encodeSerializedKeyPair


# Key Management

@docs generateKeyPair, exportKeyPair, importKeyPair, importPublicKey


# Operations

@docs publicKeyHash, deriveSharedKey

-}

import ConcurrentTask exposing (ConcurrentTask)
import Json.Decode as Decode
import Json.Encode as Encode
import WebCrypto
import WebCrypto.Symmetric as Symmetric


{-| Opaque handle to an ECDH key pair stored in JS.
-}
type KeyPair
    = KeyPair String


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


keypairIdOf : KeyPair -> String
keypairIdOf (KeyPair id) =
    id


{-| Generate a new ECDH P-256 key pair.
-}
generateKeyPair : ConcurrentTask Never KeyPair
generateKeyPair =
    ConcurrentTask.define
        { function = "webcrypto:kp:generate"
        , expect = ConcurrentTask.expectJson (Decode.map KeyPair Decode.string)
        , errors = ConcurrentTask.expectNoErrors
        , args = Encode.null
        }


{-| Export a key pair to JWK strings + public key hash.
-}
exportKeyPair : KeyPair -> ConcurrentTask WebCrypto.Error SerializedKeyPair
exportKeyPair kp =
    ConcurrentTask.define
        { function = "webcrypto:kp:export"
        , expect = ConcurrentTask.expectJson serializedKeyPairDecoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keypairId", Encode.string (keypairIdOf kp) ) ]
        }


{-| Import a key pair from JWK strings.
-}
importKeyPair : SerializedKeyPair -> ConcurrentTask WebCrypto.Error KeyPair
importKeyPair serialized =
    ConcurrentTask.define
        { function = "webcrypto:kp:import"
        , expect = ConcurrentTask.expectJson (Decode.map KeyPair Decode.string)
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "publicKey", Encode.string serialized.publicKey )
                , ( "privateKey", Encode.string serialized.privateKey )
                ]
        }


{-| Compute the SHA-256 hash of a public key (hex string).
This is the user's identity in partage.
-}
publicKeyHash : KeyPair -> ConcurrentTask WebCrypto.Error String
publicKeyHash kp =
    ConcurrentTask.define
        { function = "webcrypto:kp:publicKeyHash"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keypairId", Encode.string (keypairIdOf kp) ) ]
        }


{-| Derive a shared AES-256-GCM key from my private key and another's public key.
Uses ECDH key agreement. The result can be used for symmetric encryption.
-}
deriveSharedKey :
    { myKeyPair : KeyPair, otherPublicKey : String }
    -> ConcurrentTask WebCrypto.Error Symmetric.Key
deriveSharedKey { myKeyPair, otherPublicKey } =
    ConcurrentTask.define
        { function = "webcrypto:kp:deriveSharedKey"
        , expect = ConcurrentTask.expectJson Symmetric.keyDecoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "myKeypairId", Encode.string (keypairIdOf myKeyPair) )
                , ( "otherPublicKeyJwk", Encode.string otherPublicKey )
                ]
        }


{-| Import a public key from a JWK string (for verification or key agreement).
-}
importPublicKey : String -> ConcurrentTask WebCrypto.Error KeyPair
importPublicKey publicKeyJwk =
    ConcurrentTask.define
        { function = "webcrypto:kp:importPublicKey"
        , expect = ConcurrentTask.expectJson (Decode.map KeyPair Decode.string)
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "publicKeyJwk", Encode.string publicKeyJwk ) ]
        }
