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


{-| Opaque handle to an ECDSA signing key pair stored in JS.
-}
type SigningKeyPair
    = SigningKeyPair String


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


sigKeypairIdOf : SigningKeyPair -> String
sigKeypairIdOf (SigningKeyPair id) =
    id


{-| Generate a new ECDSA P-256 key pair for signing/verification.
-}
generateSigningKeyPair : ConcurrentTask Never SigningKeyPair
generateSigningKeyPair =
    ConcurrentTask.define
        { function = "webcrypto:sig:generate"
        , expect = ConcurrentTask.expectJson (Decode.map SigningKeyPair Decode.string)
        , errors = ConcurrentTask.expectNoErrors
        , args = Encode.null
        }


{-| Export a signing key pair to JWK strings.
-}
exportSigningKeyPair : SigningKeyPair -> ConcurrentTask WebCrypto.Error SerializedSigningKeyPair
exportSigningKeyPair skp =
    ConcurrentTask.define
        { function = "webcrypto:sig:export"
        , expect = ConcurrentTask.expectJson serializedSigningKeyPairDecoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "sigKeypairId", Encode.string (sigKeypairIdOf skp) ) ]
        }


{-| Import a signing key pair from JWK strings.
-}
importSigningKeyPair : SerializedSigningKeyPair -> ConcurrentTask WebCrypto.Error SigningKeyPair
importSigningKeyPair serialized =
    ConcurrentTask.define
        { function = "webcrypto:sig:import"
        , expect = ConcurrentTask.expectJson (Decode.map SigningKeyPair Decode.string)
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "publicKey", Encode.string serialized.publicKey )
                , ( "privateKey", Encode.string serialized.privateKey )
                ]
        }


{-| Sign data with the private key. Returns the signature as a Base64 string.
-}
sign : SigningKeyPair -> List Int -> ConcurrentTask WebCrypto.Error String
sign skp data =
    ConcurrentTask.define
        { function = "webcrypto:sig:sign"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "sigKeypairId", Encode.string (sigKeypairIdOf skp) )
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
