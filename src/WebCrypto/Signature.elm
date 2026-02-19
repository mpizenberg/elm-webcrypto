module WebCrypto.Signature exposing
    ( SigningKeyPair, SerializedSigningKeyPair, serializedSigningKeyPairDecoder, encodeSerializedSigningKeyPair
    , generateSigningKeyPair, exportSigningKeyPair, importSigningKeyPair
    , sign, verify
    )

{-| ECDSA P-256 digital signatures via WebCrypto.


# Types

@docs SigningKeyPair, SerializedSigningKeyPair, serializedSigningKeyPairDecoder, encodeSerializedSigningKeyPair


# Key Management

@docs generateSigningKeyPair, exportSigningKeyPair, importSigningKeyPair


# Operations

@docs sign, verify

-}

import ConcurrentTask exposing (ConcurrentTask)
import Json.Decode as Decode
import Json.Encode as Encode
import WebCrypto


{-| Opaque handle to an ECDSA signing key pair.
Wraps the JWK-serialized keys.
The actual `CryptoKey` objects are re-imported on the JS side for each operation.
-}
type SigningKeyPair
    = SigningKeyPair SerializedSigningKeyPair


{-| Serialized signing key pair for storage.
-}
type alias SerializedSigningKeyPair =
    { publicKey : String
    , privateKey : String
    }


{-| JSON decoder for a serialized signing key pair.
-}
serializedSigningKeyPairDecoder : Decode.Decoder SerializedSigningKeyPair
serializedSigningKeyPairDecoder =
    Decode.map2 SerializedSigningKeyPair
        (Decode.field "publicKey" Decode.string)
        (Decode.field "privateKey" Decode.string)


{-| JSON encoder for a serialized signing key pair.
-}
encodeSerializedSigningKeyPair : SerializedSigningKeyPair -> Encode.Value
encodeSerializedSigningKeyPair skp =
    Encode.object
        [ ( "publicKey", Encode.string skp.publicKey )
        , ( "privateKey", Encode.string skp.privateKey )
        ]


{-| Generate a new ECDSA P-256 key pair for signing/verification.
-}
generateSigningKeyPair : ConcurrentTask Never SigningKeyPair
generateSigningKeyPair =
    ConcurrentTask.define
        { function = "webcrypto:sig:generate"
        , expect = ConcurrentTask.expectJson (Decode.map SigningKeyPair serializedSigningKeyPairDecoder)
        , errors = ConcurrentTask.expectNoErrors
        , args = Encode.null
        }


{-| Export a signing key pair to JWK strings.
-}
exportSigningKeyPair : SigningKeyPair -> SerializedSigningKeyPair
exportSigningKeyPair (SigningKeyPair skp) =
    skp


{-| Import a signing key pair from JWK strings.
-}
importSigningKeyPair : SerializedSigningKeyPair -> SigningKeyPair
importSigningKeyPair =
    SigningKeyPair


{-| Sign data with the private key. Returns the signature as a Base64 string.
-}
sign : SigningKeyPair -> List Int -> ConcurrentTask WebCrypto.Error String
sign skp data =
    let
        serialized =
            exportSigningKeyPair skp
    in
    ConcurrentTask.define
        { function = "webcrypto:sig:sign"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "privateKeyJwk", Encode.string serialized.privateKey )
                , ( "data", Encode.list Encode.int data )
                ]
        }


{-| Verify a signature against data and a public key (JWK string).
Returns True if the signature is valid.
-}
verify : String -> String -> List Int -> ConcurrentTask WebCrypto.Error Bool
verify publicKeyJwk signature data =
    ConcurrentTask.define
        { function = "webcrypto:sig:verify"
        , expect = ConcurrentTask.expectJson Decode.bool
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "publicKeyJwk", Encode.string publicKeyJwk )
                , ( "signature", Encode.string signature )
                , ( "data", Encode.list Encode.int data )
                ]
        }
