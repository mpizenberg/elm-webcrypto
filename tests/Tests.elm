module Tests exposing (suite)

import Expect
import Json.Decode as Decode
import Json.Encode as Encode
import Test exposing (Test, describe, fuzz, test)
import Fuzz
import WebCrypto
import WebCrypto.Internal as Internal
import WebCrypto.KeyPair as KeyPair
import WebCrypto.ProofOfWork as PoW
import WebCrypto.Signature as Signature
import WebCrypto.Symmetric as Symmetric


suite : Test
suite =
    describe "elm-webcrypto pure functions"
        [ utf8Tests
        , errorDecoderTests
        , encryptedDataCodecTests
        , serializedKeyPairCodecTests
        , serializedSigningKeyPairCodecTests
        , challengeDecoderTests
        , solutionEncoderTests
        ]



-- UTF-8 round-trip


utf8Tests : Test
utf8Tests =
    describe "WebCrypto.Internal UTF-8"
        [ test "ASCII round-trip" <|
            \_ ->
                Internal.stringToBytes "hello"
                    |> Internal.bytesToString
                    |> Expect.equal (Just "hello")
        , test "ASCII bytes are correct" <|
            \_ ->
                Internal.stringToBytes "hi"
                    |> Expect.equal [ 104, 105 ]
        , test "empty string round-trip" <|
            \_ ->
                Internal.stringToBytes ""
                    |> Internal.bytesToString
                    |> Expect.equal (Just "")
        , test "empty string produces empty list" <|
            \_ ->
                Internal.stringToBytes ""
                    |> Expect.equal []
        , test "multi-byte characters round-trip (accented)" <|
            \_ ->
                Internal.stringToBytes "café"
                    |> Internal.bytesToString
                    |> Expect.equal (Just "café")
        , test "multi-byte characters round-trip (emoji)" <|
            \_ ->
                Internal.stringToBytes "hello 🌍"
                    |> Internal.bytesToString
                    |> Expect.equal (Just "hello 🌍")
        , test "multi-byte characters round-trip (CJK)" <|
            \_ ->
                Internal.stringToBytes "日本語"
                    |> Internal.bytesToString
                    |> Expect.equal (Just "日本語")
        , test "é is 2 bytes in UTF-8" <|
            \_ ->
                Internal.stringToBytes "é"
                    |> List.length
                    |> Expect.equal 2
        , test "emoji is 4 bytes in UTF-8" <|
            \_ ->
                Internal.stringToBytes "🌍"
                    |> List.length
                    |> Expect.equal 4
        , fuzz Fuzz.string "round-trip for any string" <|
            \str ->
                Internal.stringToBytes str
                    |> Internal.bytesToString
                    |> Expect.equal (Just str)
        ]



-- Error decoder


errorDecoderTests : Test
errorDecoderTests =
    describe "WebCrypto.errorDecoder"
        [ test "decodes ENCRYPTION_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"ENCRYPTION_FAILED:bad data\""
                    |> Expect.equal (Ok (WebCrypto.EncryptionFailed "bad data"))
        , test "decodes DECRYPTION_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"DECRYPTION_FAILED:Invalid key or corrupted data\""
                    |> Expect.equal (Ok (WebCrypto.DecryptionFailed "Invalid key or corrupted data"))
        , test "decodes KEY_GENERATION_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"KEY_GENERATION_FAILED:out of entropy\""
                    |> Expect.equal (Ok (WebCrypto.KeyGenerationFailed "out of entropy"))
        , test "decodes KEY_IMPORT_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"KEY_IMPORT_FAILED:invalid format\""
                    |> Expect.equal (Ok (WebCrypto.KeyImportFailed "invalid format"))
        , test "decodes KEY_EXPORT_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"KEY_EXPORT_FAILED:not extractable\""
                    |> Expect.equal (Ok (WebCrypto.KeyExportFailed "not extractable"))
        , test "decodes KEY_DERIVATION_FAILED as InvalidKey" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"KEY_DERIVATION_FAILED:bad curve\""
                    |> Expect.equal (Ok (WebCrypto.InvalidKey "bad curve"))
        , test "decodes SIGNING_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"SIGNING_FAILED:key not usable\""
                    |> Expect.equal (Ok (WebCrypto.SigningFailed "key not usable"))
        , test "decodes VERIFICATION_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"VERIFICATION_FAILED:bad signature\""
                    |> Expect.equal (Ok (WebCrypto.VerificationFailed "bad signature"))
        , test "decodes HASHING_FAILED" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"HASHING_FAILED:unknown algo\""
                    |> Expect.equal (Ok (WebCrypto.HashingFailed "unknown algo"))
        , test "decodes INVALID_KEY" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"INVALID_KEY:Key not found\""
                    |> Expect.equal (Ok (WebCrypto.InvalidKey "Key not found"))
        , test "message preserves colons after the first" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"HASHING_FAILED:error: something: bad\""
                    |> Expect.equal (Ok (WebCrypto.HashingFailed "error: something: bad"))
        , test "fails on unknown error code" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"UNKNOWN_CODE:message\""
                    |> Expect.err
        , test "fails on string without colon" <|
            \_ ->
                Decode.decodeString WebCrypto.errorDecoder "\"no separator\""
                    |> Expect.err
        ]



-- EncryptedData codec


encryptedDataCodecTests : Test
encryptedDataCodecTests =
    describe "Symmetric.EncryptedData codec"
        [ test "round-trip" <|
            \_ ->
                let
                    data =
                        { ciphertext = "Y2lwaGVydGV4dA==", iv = "aXY=" }
                in
                Symmetric.encodeEncryptedData data
                    |> Decode.decodeValue Symmetric.encryptedDataDecoder
                    |> Expect.equal (Ok data)
        , test "decodes correct JSON" <|
            \_ ->
                """{"ciphertext":"abc123","iv":"def456"}"""
                    |> Decode.decodeString Symmetric.encryptedDataDecoder
                    |> Expect.equal (Ok { ciphertext = "abc123", iv = "def456" })
        , test "encoder produces correct fields" <|
            \_ ->
                let
                    encoded =
                        Symmetric.encodeEncryptedData { ciphertext = "ct", iv = "iv" }
                in
                ( Decode.decodeValue (Decode.field "ciphertext" Decode.string) encoded
                , Decode.decodeValue (Decode.field "iv" Decode.string) encoded
                )
                    |> Expect.equal ( Ok "ct", Ok "iv" )
        , test "decoder fails on missing ciphertext" <|
            \_ ->
                """{"iv":"abc"}"""
                    |> Decode.decodeString Symmetric.encryptedDataDecoder
                    |> Expect.err
        , test "decoder fails on missing iv" <|
            \_ ->
                """{"ciphertext":"abc"}"""
                    |> Decode.decodeString Symmetric.encryptedDataDecoder
                    |> Expect.err
        ]



-- SerializedKeyPair codec


serializedKeyPairCodecTests : Test
serializedKeyPairCodecTests =
    describe "KeyPair.SerializedKeyPair codec"
        [ test "round-trip" <|
            \_ ->
                let
                    skp =
                        { publicKey = "{\"kty\":\"EC\"}"
                        , privateKey = "{\"kty\":\"EC\",\"d\":\"...\"}"
                        , publicKeyHash = "abcdef1234567890"
                        }
                in
                KeyPair.encodeSerializedKeyPair skp
                    |> Decode.decodeValue KeyPair.serializedKeyPairDecoder
                    |> Expect.equal (Ok skp)
        , test "decoder fails on missing publicKeyHash" <|
            \_ ->
                """{"publicKey":"pk","privateKey":"sk"}"""
                    |> Decode.decodeString KeyPair.serializedKeyPairDecoder
                    |> Expect.err
        ]



-- SerializedSigningKeyPair codec


serializedSigningKeyPairCodecTests : Test
serializedSigningKeyPairCodecTests =
    describe "Signature.SerializedSigningKeyPair codec"
        [ test "round-trip" <|
            \_ ->
                let
                    skp =
                        { publicKey = "{\"kty\":\"EC\"}"
                        , privateKey = "{\"kty\":\"EC\",\"d\":\"...\"}"
                        }
                in
                Signature.encodeSerializedSigningKeyPair skp
                    |> Decode.decodeValue Signature.serializedSigningKeyPairDecoder
                    |> Expect.equal (Ok skp)
        , test "decoder fails on missing privateKey" <|
            \_ ->
                """{"publicKey":"pk"}"""
                    |> Decode.decodeString Signature.serializedSigningKeyPairDecoder
                    |> Expect.err
        ]



-- Challenge decoder


challengeDecoderTests : Test
challengeDecoderTests =
    describe "ProofOfWork.challengeDecoder"
        [ test "decodes valid challenge" <|
            \_ ->
                """{"challenge":"abc","timestamp":1700000000,"difficulty":18,"signature":"sig123"}"""
                    |> Decode.decodeString PoW.challengeDecoder
                    |> Expect.equal
                        (Ok
                            { challenge = "abc"
                            , timestamp = 1700000000
                            , difficulty = 18
                            , signature = "sig123"
                            }
                        )
        , test "fails on missing difficulty" <|
            \_ ->
                """{"challenge":"abc","timestamp":1700000000,"signature":"sig"}"""
                    |> Decode.decodeString PoW.challengeDecoder
                    |> Expect.err
        ]



-- Solution encoder


solutionEncoderTests : Test
solutionEncoderTests =
    describe "ProofOfWork.encodeSolution"
        [ test "encodes all fields with correct names" <|
            \_ ->
                let
                    solution =
                        { pow_challenge = "abc"
                        , pow_timestamp = 1700000000
                        , pow_difficulty = 18
                        , pow_signature = "sig123"
                        , pow_solution = "42"
                        }

                    encoded =
                        PoW.encodeSolution solution
                in
                ( Decode.decodeValue (Decode.field "pow_challenge" Decode.string) encoded
                , Decode.decodeValue (Decode.field "pow_timestamp" Decode.int) encoded
                , Decode.decodeValue (Decode.field "pow_solution" Decode.string) encoded
                )
                    |> Expect.equal ( Ok "abc", Ok 1700000000, Ok "42" )
        , test "round-trip through JSON" <|
            \_ ->
                let
                    solution =
                        { pow_challenge = "test"
                        , pow_timestamp = 123
                        , pow_difficulty = 10
                        , pow_signature = "s"
                        , pow_solution = "99"
                        }

                    decoder =
                        Decode.map5
                            (\c t d s n ->
                                { pow_challenge = c
                                , pow_timestamp = t
                                , pow_difficulty = d
                                , pow_signature = s
                                , pow_solution = n
                                }
                            )
                            (Decode.field "pow_challenge" Decode.string)
                            (Decode.field "pow_timestamp" Decode.int)
                            (Decode.field "pow_difficulty" Decode.int)
                            (Decode.field "pow_signature" Decode.string)
                            (Decode.field "pow_solution" Decode.string)
                in
                PoW.encodeSolution solution
                    |> Decode.decodeValue decoder
                    |> Expect.equal (Ok solution)
        ]
