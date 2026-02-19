module WebCrypto.Internal exposing (stringToBytes, bytesToString)

{-| Internal UTF-8 conversion helpers using elm/bytes.

Not exposed in elm.json -- only used by other modules in this package.

-}

import Bytes
import Bytes.Decode
import Bytes.Encode


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


{-| Decode a List Int of UTF-8 bytes to a String.
Returns Nothing if the bytes are not valid UTF-8.
-}
bytesToString : List Int -> Maybe String
bytesToString ints =
    let
        encoded =
            Bytes.Encode.encode
                (Bytes.Encode.sequence (List.map Bytes.Encode.unsignedInt8 ints))
    in
    Bytes.Decode.decode (Bytes.Decode.string (Bytes.width encoded)) encoded



-- Internal


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
