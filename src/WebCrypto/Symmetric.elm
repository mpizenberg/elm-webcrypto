module WebCrypto.Symmetric exposing
    ( Key, keyDecoder, EncryptedData
    , generateKey, exportKey, importKey
    , encrypt, decrypt
    , encryptString, decryptString
    , encryptJson, decryptJson
    )

{-| AES-256-GCM symmetric encryption via WebCrypto.


# Types

@docs Key, keyDecoder, EncryptedData


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


encryptedDataDecoder : Decode.Decoder EncryptedData
encryptedDataDecoder =
    Decode.map2 EncryptedData
        (Decode.field "ciphertext" Decode.string)
        (Decode.field "iv" Decode.string)


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
    ConcurrentTask.define
        { function = "webcrypto:sym:encryptString"
        , expect = ConcurrentTask.expectJson encryptedDataDecoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) )
                , ( "plaintext", Encode.string plaintext )
                ]
        }


{-| Decrypt to a string. Decodes UTF-8 after decryption.
-}
decryptString : Key -> EncryptedData -> ConcurrentTask WebCrypto.Error String
decryptString key encrypted =
    ConcurrentTask.define
        { function = "webcrypto:sym:decryptString"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) )
                , ( "ciphertext", Encode.string encrypted.ciphertext )
                , ( "iv", Encode.string encrypted.iv )
                ]
        }


{-| Encrypt a JSON value. Serializes to JSON string, then encrypts.
-}
encryptJson : Key -> Encode.Value -> ConcurrentTask WebCrypto.Error EncryptedData
encryptJson key json =
    ConcurrentTask.define
        { function = "webcrypto:sym:encryptJson"
        , expect = ConcurrentTask.expectJson encryptedDataDecoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) )
                , ( "json", json )
                ]
        }


{-| Decrypt a JSON value. Decrypts, then parses JSON.
Uses the provided decoder to produce a typed value.
-}
decryptJson : Key -> Decode.Decoder a -> EncryptedData -> ConcurrentTask WebCrypto.Error a
decryptJson key decoder encrypted =
    ConcurrentTask.define
        { function = "webcrypto:sym:decryptJson"
        , expect = ConcurrentTask.expectJson decoder
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "keyId", Encode.string (keyIdOf key) )
                , ( "ciphertext", Encode.string encrypted.ciphertext )
                , ( "iv", Encode.string encrypted.iv )
                ]
        }


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
