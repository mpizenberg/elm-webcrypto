module WebCrypto.ProofOfWork exposing
    ( Challenge, Solution
    , solveChallenge
    )

{-| SHA-256 Proof-of-Work solver via WebCrypto.

Runs the brute force loop in a Web Worker to avoid blocking the UI thread.


# Types

@docs Challenge, Solution


# Solving

@docs solveChallenge

-}

import ConcurrentTask exposing (ConcurrentTask)
import Json.Decode as Decode
import Json.Encode as Encode
import WebCrypto


{-| A Proof-of-Work challenge from the server.
-}
type alias Challenge =
    { challenge : String
    , timestamp : Int
    , difficulty : Int
    , signature : String
    }


{-| A solved Proof-of-Work challenge, ready to send back to the server.
-}
type alias Solution =
    { pow_challenge : String
    , pow_timestamp : Int
    , pow_difficulty : Int
    , pow_signature : String
    , pow_solution : String
    }


{-| Solve a Proof-of-Work challenge.
Runs SHA-256 brute force in a Web Worker to avoid blocking the UI.
Finds a nonce such that SHA-256(challenge + nonce) has `difficulty` leading zero bits.
-}
solveChallenge : Challenge -> ConcurrentTask WebCrypto.Error Solution
solveChallenge challenge =
    ConcurrentTask.define
        { function = "webcrypto:pow:solve"
        , expect = ConcurrentTask.expectString
        , errors = ConcurrentTask.expectErrors WebCrypto.errorDecoder
        , args =
            Encode.object
                [ ( "challenge", Encode.string challenge.challenge )
                , ( "difficulty", Encode.int challenge.difficulty )
                ]
        }
        |> ConcurrentTask.map
            (\nonce ->
                { pow_challenge = challenge.challenge
                , pow_timestamp = challenge.timestamp
                , pow_difficulty = challenge.difficulty
                , pow_signature = challenge.signature
                , pow_solution = nonce
                }
            )
