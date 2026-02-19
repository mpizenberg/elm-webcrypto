module WebCrypto.Symmetric exposing
    ( Key, keyDecoder, EncryptedData, encryptedDataDecoder, encodeEncryptedData
    , generateKey, exportKey, importKey
    , encrypt, decrypt
    , encryptString, decryptString
    , encryptJson, decryptJson
    )

{-| AES-256-GCM symmetric encryption via WebCrypto.


# Types

@docs Key, keyDecoder, EncryptedData, encryptedDataDecoder, encodeEncryptedData


# Key Management

@docs generateKey, exportKey, importKey


# Raw Bytes

@docs encrypt, decrypt


# Strings

@docs encryptString, decryptString


# JSON

@docs encryptJson, decryptJson

-}

import ConcurrentTask exposing (ConcurrentTask)
import Json.Decode as Decode
import Json.Encode as Encode
import WebCrypto
import WebCrypto.Internal as Internal


{-| Opaque handle to an AES-256-GCM key stored in JS.
Cannot be inspected from Elm -- only used as a parameter to crypto operations.
-}
type Key
    = Key String


{-| Encrypted data: ciphertext + initialization vector.
Both are represented as Base64 strings for safe JSON serialization.
-}
type alias EncryptedData =
    { ciphertext : String
    , iv : String
    }


{-| JSON decoder for encrypted data.
-}
encryptedDataDecoder : Decode.Decoder EncryptedData
encryptedDataDecoder =
    Decode.map2 EncryptedData
        (Decode.field "ciphertext" Decode.string)
        (Decode.field "iv" Decode.string)


{-| JSON encoder for encrypted data.
-}
encodeEncryptedData : EncryptedData -> Encode.Value
encodeEncryptedData data =
    Encode.object
        [ ( "ciphertext", Encode.string data.ciphertext )
        , ( "iv", Encode.string data.iv )
        ]


{-| JSON decoder for a symmetric key handle.
Decodes the string ID returned by JS key operations.
-}
keyDecoder : Decode.Decoder Key
keyDecoder =
    Decode.map Key Decode.string


keyIdOf : Key -> String
keyIdOf (Key id) =
    id


{-| Generate a new random AES-256-GCM key.
-}
generateKey : ConcurrentTask Never Key
generateKey =
    ConcurrentTask.define
        { function = "webcrypto:sym:generateKey"
        , expect = ConcurrentTask.expectJson (Decode.map Key Decode.string)
        , errors = ConcurrentTask.expectNoErrors
        , args = Encode.null
        }


{-| Encrypt raw bytes with AES-256-GCM.
Generates a random 96-bit IV. Returns ciphertext (with appended auth tag) and IV.
-}
encrypt : Key -> List Int -> ConcurrentTask WebCrypto.Error EncryptedData
encrypt key data =
    ConcurrentTask.define
        { function = "webcrypto:sym:encrypt"
        , expect = ConcurrentTask.expectJson encryptedDataDecoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) )
                , ( "data", Encode.list Encode.int data )
                ]
        }


{-| Decrypt data encrypted with AES-256-GCM.
Verifies the authentication tag. Fails if key is wrong or data is corrupted.
-}
decrypt : Key -> EncryptedData -> ConcurrentTask WebCrypto.Error (List Int)
decrypt key encrypted =
    ConcurrentTask.define
        { function = "webcrypto:sym:decrypt"
        , expect = ConcurrentTask.expectJson (Decode.list Decode.int)
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) )
                , ( "ciphertext", Encode.string encrypted.ciphertext )
                , ( "iv", Encode.string encrypted.iv )
                ]
        }


{-| Encrypt a string. Encodes to UTF-8 before encryption.
-}
encryptString : Key -> String -> ConcurrentTask WebCrypto.Error EncryptedData
encryptString key plaintext =
    encrypt key (Internal.stringToBytes plaintext)


{-| Decrypt to a string. Decodes UTF-8 after decryption.
-}
decryptString : Key -> EncryptedData -> ConcurrentTask WebCrypto.Error String
decryptString key encrypted =
    decrypt key encrypted
        |> ConcurrentTask.andThen
            (\bytes ->
                case Internal.bytesToString bytes of
                    Just str ->
                        ConcurrentTask.succeed str

                    Nothing ->
                        ConcurrentTask.fail (WebCrypto.DecryptionFailed "Invalid UTF-8 in decrypted data")
            )


{-| Encrypt a JSON value. Serializes to JSON string, then encrypts.
-}
encryptJson : Key -> Encode.Value -> ConcurrentTask WebCrypto.Error EncryptedData
encryptJson key json =
    encryptString key (Encode.encode 0 json)


{-| Decrypt a JSON value. Decrypts, then parses JSON.
Uses the provided decoder to produce a typed value.
-}
decryptJson : Key -> Decode.Decoder a -> EncryptedData -> ConcurrentTask WebCrypto.Error a
decryptJson key decoder encrypted =
    decryptString key encrypted
        |> ConcurrentTask.andThen
            (\jsonStr ->
                case Decode.decodeString decoder jsonStr of
                    Ok val ->
                        ConcurrentTask.succeed val

                    Err err ->
                        ConcurrentTask.fail (WebCrypto.DecryptionFailed ("JSON decode error: " ++ Decode.errorToString err))
            )


{-| Export a key to a Base64 string for storage (e.g. in IndexedDB).
-}
exportKey : Key -> ConcurrentTask WebCrypto.Error String
exportKey key =
    ConcurrentTask.define
        { function = "webcrypto:sym:exportKey"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) ) ]
        }


{-| Import a key from a Base64 string.
-}
importKey : String -> ConcurrentTask WebCrypto.Error Key
importKey base64 =
    ConcurrentTask.define
        { function = "webcrypto:sym:importKey"
        , expect = ConcurrentTask.expectJson (Decode.map Key Decode.string)
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "base64", Encode.string base64 ) ]
        }
