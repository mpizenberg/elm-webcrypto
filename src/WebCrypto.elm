module WebCrypto exposing
    ( Error(..), errorDecoder
    , sha256, sha256Hex
    )

{-| WebCrypto API for Elm via elm-concurrent-task.

Wraps the browser's WebCrypto API as composable `ConcurrentTask` values.


# Error Handling

@docs Error, errorDecoder


# Hashing

@docs sha256, sha256Hex

-}

import ConcurrentTask exposing (ConcurrentTask)
import Json.Decode as Decode
import Json.Encode as Encode


{-| Errors that can occur during WebCrypto operations.
-}
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


{-| Decoder for WebCrypto errors returned from JS.

Errors are encoded as `"CODE:message"` strings.

-}
errorDecoder : Decode.Decoder Error
errorDecoder =
    Decode.string
        |> Decode.andThen
            (\err ->
                case splitOnce ":" err of
                    Just ( "ENCRYPTION_FAILED", msg ) ->
                        Decode.succeed (EncryptionFailed msg)

                    Just ( "DECRYPTION_FAILED", msg ) ->
                        Decode.succeed (DecryptionFailed msg)

                    Just ( "KEY_GENERATION_FAILED", msg ) ->
                        Decode.succeed (KeyGenerationFailed msg)

                    Just ( "KEY_IMPORT_FAILED", msg ) ->
                        Decode.succeed (KeyImportFailed msg)

                    Just ( "KEY_EXPORT_FAILED", msg ) ->
                        Decode.succeed (KeyExportFailed msg)

                    Just ( "KEY_DERIVATION_FAILED", msg ) ->
                        Decode.succeed (InvalidKey msg)

                    Just ( "SIGNING_FAILED", msg ) ->
                        Decode.succeed (SigningFailed msg)

                    Just ( "VERIFICATION_FAILED", msg ) ->
                        Decode.succeed (VerificationFailed msg)

                    Just ( "HASHING_FAILED", msg ) ->
                        Decode.succeed (HashingFailed msg)

                    Just ( "INVALID_KEY", msg ) ->
                        Decode.succeed (InvalidKey msg)

                    _ ->
                        Decode.fail ("Unknown WebCrypto error: " ++ err)
            )


{-| Split a string on the first occurrence of a separator.

    splitOnce ":" "FOO:bar:baz" == Just ( "FOO", "bar:baz" )

    splitOnce ":" "no separator" == Nothing

-}
splitOnce : String -> String -> Maybe ( String, String )
splitOnce sep str =
    case String.indexes sep str of
        first :: _ ->
            Just
                ( String.left first str
                , String.dropLeft (first + String.length sep) str
                )

        [] ->
            Nothing


{-| Compute SHA-256 hash of a string. Returns hex string.
-}
sha256 : String -> ConcurrentTask Error String
sha256 str =
    ConcurrentTask.define
        { function = "webcrypto:sha256hex"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors errorDecoder
        , args = Encode.object [ ( "data", Encode.string str ) ]
        }


{-| Compute SHA-256 hash of raw bytes. Returns hex string.
-}
sha256Hex : List Int -> ConcurrentTask Error String
sha256Hex bytes =
    ConcurrentTask.define
        { function = "webcrypto:sha256hex"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors errorDecoder
        , args = Encode.object [ ( "data", Encode.list Encode.int bytes ) ]
        }
