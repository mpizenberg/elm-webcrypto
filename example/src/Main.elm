port module Main exposing (main)

import Browser
import Bytes
import Bytes.Decode
import Bytes.Encode
import ConcurrentTask exposing (ConcurrentTask)
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick)
import Json.Decode as Decode
import WebCrypto
import WebCrypto.KeyPair as KeyPair
import WebCrypto.Signature as Signature
import WebCrypto.Symmetric as Symmetric



-- MAIN


main : Program () Model Msg
main =
    Browser.element
        { init = init
        , update = update
        , subscriptions = subscriptions
        , view = view
        }



-- PORTS


port send : Decode.Value -> Cmd msg


port receive : (Decode.Value -> msg) -> Sub msg



-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions model =
    ConcurrentTask.onProgress
        { send = send
        , receive = receive
        , onProgress = OnProgress
        }
        model.pool



-- MODEL


type alias Model =
    { pool : ConcurrentTask.Pool Msg
    , hashResult : Maybe String
    , symmetricResult : Maybe String
    , keyExchangeResult : Maybe String
    , signatureResult : Maybe String
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { pool = ConcurrentTask.pool
      , hashResult = Nothing
      , symmetricResult = Nothing
      , keyExchangeResult = Nothing
      , signatureResult = Nothing
      }
    , Cmd.none
    )



-- UPDATE


type Msg
    = RunHash
    | RunSymmetric
    | RunKeyExchange
    | RunSignature
    | OnHashComplete (ConcurrentTask.Response WebCrypto.Error String)
    | OnSymmetricComplete (ConcurrentTask.Response WebCrypto.Error String)
    | OnKeyExchangeComplete (ConcurrentTask.Response WebCrypto.Error String)
    | OnSignatureComplete (ConcurrentTask.Response WebCrypto.Error String)
    | OnProgress ( ConcurrentTask.Pool Msg, Cmd Msg )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        RunHash ->
            let
                ( pool, cmd ) =
                    ConcurrentTask.attempt
                        { send = send
                        , pool = model.pool
                        , onComplete = OnHashComplete
                        }
                        hashTask
            in
            ( { model | pool = pool, hashResult = Just "Computing..." }, cmd )

        RunSymmetric ->
            let
                ( pool, cmd ) =
                    ConcurrentTask.attempt
                        { send = send
                        , pool = model.pool
                        , onComplete = OnSymmetricComplete
                        }
                        symmetricTask
            in
            ( { model | pool = pool, symmetricResult = Just "Computing..." }, cmd )

        RunKeyExchange ->
            let
                ( pool, cmd ) =
                    ConcurrentTask.attempt
                        { send = send
                        , pool = model.pool
                        , onComplete = OnKeyExchangeComplete
                        }
                        keyExchangeTask
            in
            ( { model | pool = pool, keyExchangeResult = Just "Computing..." }, cmd )

        RunSignature ->
            let
                ( pool, cmd ) =
                    ConcurrentTask.attempt
                        { send = send
                        , pool = model.pool
                        , onComplete = OnSignatureComplete
                        }
                        signatureTask
            in
            ( { model | pool = pool, signatureResult = Just "Computing..." }, cmd )

        OnHashComplete response ->
            ( { model | hashResult = Just (responseToString response) }, Cmd.none )

        OnSymmetricComplete response ->
            ( { model | symmetricResult = Just (responseToString response) }, Cmd.none )

        OnKeyExchangeComplete response ->
            ( { model | keyExchangeResult = Just (responseToString response) }, Cmd.none )

        OnSignatureComplete response ->
            ( { model | signatureResult = Just (responseToString response) }, Cmd.none )

        OnProgress ( pool, cmd ) ->
            ( { model | pool = pool }, cmd )


responseToString : ConcurrentTask.Response WebCrypto.Error String -> String
responseToString response =
    case response of
        ConcurrentTask.Success value ->
            value

        ConcurrentTask.Error err ->
            "Error: " ++ errorToString err

        ConcurrentTask.UnexpectedError err ->
            "Unexpected error: " ++ unexpectedErrorToString err


errorToString : WebCrypto.Error -> String
errorToString err =
    case err of
        WebCrypto.EncryptionFailed msg_ ->
            "Encryption failed: " ++ msg_

        WebCrypto.DecryptionFailed msg_ ->
            "Decryption failed: " ++ msg_

        WebCrypto.KeyGenerationFailed msg_ ->
            "Key generation failed: " ++ msg_

        WebCrypto.KeyImportFailed msg_ ->
            "Key import failed: " ++ msg_

        WebCrypto.KeyExportFailed msg_ ->
            "Key export failed: " ++ msg_

        WebCrypto.SigningFailed msg_ ->
            "Signing failed: " ++ msg_

        WebCrypto.VerificationFailed msg_ ->
            "Verification failed: " ++ msg_

        WebCrypto.HashingFailed msg_ ->
            "Hashing failed: " ++ msg_

        WebCrypto.InvalidKey msg_ ->
            "Invalid key: " ++ msg_


unexpectedErrorToString : ConcurrentTask.UnexpectedError -> String
unexpectedErrorToString err =
    case err of
        ConcurrentTask.MissingFunction name ->
            "Missing JS function: " ++ name

        ConcurrentTask.ResponseDecoderFailure { function } ->
            "Response decoder failed for: " ++ function

        ConcurrentTask.ErrorsDecoderFailure { function } ->
            "Error decoder failed for: " ++ function

        ConcurrentTask.UnhandledJsException { function, message } ->
            function ++ " threw: " ++ message

        ConcurrentTask.InternalError message ->
            "Internal error: " ++ message



-- TASKS


{-| SHA-256 hash of "Hello, World!" — returns hex digest.
-}
hashTask : ConcurrentTask WebCrypto.Error String
hashTask =
    WebCrypto.sha256 "Hello, World!"


{-| Generate a key → encrypt "secret message" → decrypt → show roundtrip.
-}
symmetricTask : ConcurrentTask WebCrypto.Error String
symmetricTask =
    let
        plaintext =
            "secret message"
    in
    Symmetric.generateKey
        |> ConcurrentTask.mapError never
        |> ConcurrentTask.andThen
            (\key ->
                Symmetric.encryptString key plaintext
                    |> ConcurrentTask.andThen
                        (\encrypted ->
                            Symmetric.decryptString key encrypted
                                |> ConcurrentTask.map
                                    (\decrypted ->
                                        "Encrypted & decrypted: \"" ++ decrypted ++ "\""
                                    )
                        )
            )


{-| Generate 2 ECDH key pairs → derive shared key from each side →
encrypt with Alice's shared key, decrypt with Bob's → show roundtrip.
-}
keyExchangeTask : ConcurrentTask WebCrypto.Error String
keyExchangeTask =
    ConcurrentTask.map2 Tuple.pair
        (KeyPair.generateKeyPair |> ConcurrentTask.mapError never)
        (KeyPair.generateKeyPair |> ConcurrentTask.mapError never)
        |> ConcurrentTask.andThen
            (\( alice, bob ) ->
                let
                    alicePub =
                        (KeyPair.exportKeyPair alice).publicKey

                    bobPub =
                        (KeyPair.exportKeyPair bob).publicKey
                in
                ConcurrentTask.map2 Tuple.pair
                    (KeyPair.deriveSharedKey { myKeyPair = alice, otherPublicKey = bobPub })
                    (KeyPair.deriveSharedKey { myKeyPair = bob, otherPublicKey = alicePub })
                    |> ConcurrentTask.andThen
                        (\( aliceKey, bobKey ) ->
                            Symmetric.encryptString aliceKey "Hello from Alice!"
                                |> ConcurrentTask.andThen
                                    (\encrypted ->
                                        Symmetric.decryptString bobKey encrypted
                                            |> ConcurrentTask.map
                                                (\decrypted ->
                                                    "Alice encrypted, Bob decrypted: \"" ++ decrypted ++ "\""
                                                )
                                    )
                        )
            )


{-| Generate signing key pair → sign a message → verify with public key.
-}
signatureTask : ConcurrentTask WebCrypto.Error String
signatureTask =
    let
        message =
            stringToBytes "Sign this message"
    in
    Signature.generateSigningKeyPair
        |> ConcurrentTask.mapError never
        |> ConcurrentTask.andThen
            (\keyPair ->
                Signature.sign keyPair message
                    |> ConcurrentTask.andThen
                        (\sig ->
                            let
                                pubKey =
                                    (Signature.exportSigningKeyPair keyPair).publicKey
                            in
                            Signature.verify pubKey sig message
                                |> ConcurrentTask.map
                                    (\valid ->
                                        "Signature valid: "
                                            ++ (if valid then
                                                    "True"

                                                else
                                                    "False"
                                               )
                                    )
                        )
            )



-- HELPERS


{-| Encode a String to UTF-8 bytes as a List Int.
-}
stringToBytes : String -> List Int
stringToBytes str =
    let
        encoded =
            Bytes.Encode.encode (Bytes.Encode.string str)
    in
    Bytes.Decode.decode (bytesListDecoder (Bytes.width encoded)) encoded
        |> Maybe.withDefault []


bytesListDecoder : Int -> Bytes.Decode.Decoder (List Int)
bytesListDecoder width =
    Bytes.Decode.loop ( width, [] ) bytesListStep


bytesListStep : ( Int, List Int ) -> Bytes.Decode.Decoder (Bytes.Decode.Step ( Int, List Int ) (List Int))
bytesListStep ( remaining, acc ) =
    if remaining <= 0 then
        Bytes.Decode.succeed (Bytes.Decode.Done (List.reverse acc))

    else
        Bytes.Decode.unsignedInt8
            |> Bytes.Decode.map (\byte -> Bytes.Decode.Loop ( remaining - 1, byte :: acc ))



-- VIEW


view : Model -> Html Msg
view model =
    div
        [ style "font-family" "sans-serif"
        , style "max-width" "600px"
        , style "margin" "40px auto"
        , style "padding" "20px"
        ]
        [ h1 [] [ text "elm-webcrypto Demo" ]
        , p [] [ text "Click each button to run a WebCrypto demo." ]
        , viewDemo "1. SHA-256 Hashing"
            "Hash \"Hello, World!\" and display the hex digest."
            RunHash
            model.hashResult
        , viewDemo "2. Symmetric Encrypt / Decrypt"
            "Generate an AES-256-GCM key, encrypt \"secret message\", then decrypt it."
            RunSymmetric
            model.symmetricResult
        , viewDemo "3. ECDH Key Exchange"
            "Generate two ECDH key pairs, derive shared keys, encrypt with Alice's key and decrypt with Bob's."
            RunKeyExchange
            model.keyExchangeResult
        , viewDemo "4. Sign & Verify"
            "Generate an ECDSA key pair, sign a message, and verify the signature."
            RunSignature
            model.signatureResult
        ]


viewDemo : String -> String -> Msg -> Maybe String -> Html Msg
viewDemo title description action result =
    div
        [ style "margin-bottom" "24px"
        , style "padding" "16px"
        , style "border" "1px solid #ddd"
        , style "border-radius" "8px"
        ]
        [ h3 [ style "margin-top" "0" ] [ text title ]
        , p [ style "color" "#666", style "margin" "0 0 12px 0" ] [ text description ]
        , button
            [ onClick action
            , style "padding" "8px 16px"
            , style "cursor" "pointer"
            ]
            [ text "Run" ]
        , case result of
            Just value ->
                pre
                    [ style "margin" "12px 0 0 0"
                    , style "padding" "10px"
                    , style "background" "#f5f5f5"
                    , style "border-radius" "4px"
                    , style "white-space" "pre-wrap"
                    , style "word-break" "break-all"
                    ]
                    [ text value ]

            Nothing ->
                text ""
        ]
