# elm-webcrypto example

Interactive demo of the elm-webcrypto API: hashing, symmetric encryption, key exchange, and digital signatures.

## Setup

```sh
npm install
```

## Build

```sh
elm make src/Main.elm --output static/elm.js
npx esbuild src/index.js --bundle --outfile=static/main.js
```

## Run

```sh
python -m http.server
```

Open http://localhost:8000 and click each "Run" button to exercise the demos.
