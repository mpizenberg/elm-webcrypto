// js/src/index.js
//
// Stateless WebCrypto task runners.
// No Maps or closures -- key material is owned by Elm and
// re-imported into CryptoKey objects on each operation.

export function createTasks() {
  // --- Helpers ---

  function toBase64(uint8array) {
    return btoa(String.fromCharCode(...uint8array));
  }

  function fromBase64(base64) {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  function importAesKey(base64) {
    return crypto.subtle.importKey(
      "raw",
      fromBase64(base64),
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
  }

  function toHex(uint8array) {
    return Array.from(uint8array)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  return {
    // --- SHA-256 ---

    "webcrypto:sha256hex": async ({ data }) => {
      try {
        const hashBuffer = await crypto.subtle.digest(
          "SHA-256",
          new Uint8Array(data),
        );
        return toHex(new Uint8Array(hashBuffer));
      } catch (e) {
        return { error: "HASHING_FAILED:" + e.message };
      }
    },

    // --- Symmetric (AES-256-GCM) ---

    "webcrypto:sym:generateKey": async () => {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      const exported = await crypto.subtle.exportKey("raw", key);
      return toBase64(new Uint8Array(exported));
    },

    "webcrypto:sym:encrypt": async ({ key, data }) => {
      try {
        const cryptoKey = await importAesKey(key);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          cryptoKey,
          new Uint8Array(data),
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decrypt": async ({ key, ciphertext, iv }) => {
      try {
        const cryptoKey = await importAesKey(key);
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          cryptoKey,
          fromBase64(ciphertext),
        );
        return Array.from(new Uint8Array(decrypted));
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    // --- Key Pair (ECDH P-256) ---

    "webcrypto:kp:generate": async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"],
      );
      const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
      const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
      const rawBytes = await crypto.subtle.exportKey("raw", kp.publicKey);
      const hashBuffer = await crypto.subtle.digest("SHA-256", rawBytes);
      return {
        publicKey: JSON.stringify(pubJwk),
        privateKey: JSON.stringify(privJwk),
        publicKeyHash: toHex(new Uint8Array(hashBuffer)),
      };
    },

    "webcrypto:kp:deriveSharedKey": async ({
      myPrivateKeyJwk,
      otherPublicKeyJwk,
    }) => {
      try {
        const myPrivKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(myPrivateKeyJwk),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey"],
        );
        const otherPub = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(otherPublicKeyJwk),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          [],
        );
        const sharedKey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: otherPub },
          myPrivKey,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"],
        );
        const exported = await crypto.subtle.exportKey("raw", sharedKey);
        return toBase64(new Uint8Array(exported));
      } catch (e) {
        return { error: "KEY_DERIVATION_FAILED:" + e.message };
      }
    },

    // --- Signing (ECDSA P-256) ---

    "webcrypto:sig:generate": async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
      const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
      return {
        publicKey: JSON.stringify(pubJwk),
        privateKey: JSON.stringify(privJwk),
      };
    },

    "webcrypto:sig:sign": async ({ privateKeyJwk, data }) => {
      try {
        const privKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(privateKeyJwk),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign"],
        );
        const signature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          privKey,
          new Uint8Array(data),
        );
        return toBase64(new Uint8Array(signature));
      } catch (e) {
        return { error: "SIGNING_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:verify": async ({ publicKeyJwk, signature, data }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKeyJwk),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        );
        return await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          pubKey,
          fromBase64(signature),
          new Uint8Array(data),
        );
      } catch (e) {
        return { error: "VERIFICATION_FAILED:" + e.message };
      }
    },

    // --- Proof of Work ---

    "webcrypto:pow:solve": ({ challenge, difficulty }) => {
      return new Promise((resolve) => {
        const workerCode = `
          async function solve(challenge, difficulty) {
            const encoder = new TextEncoder();
            let nonce = 0;
            while (true) {
              const input = challenge + String(nonce);
              const hashBuffer = await crypto.subtle.digest(
                "SHA-256",
                encoder.encode(input)
              );
              const hashArray = new Uint8Array(hashBuffer);
              if (checkDifficulty(hashArray, difficulty)) {
                return String(nonce);
              }
              nonce++;
            }
          }

          function checkDifficulty(hashBytes, difficulty) {
            const fullBytes = Math.floor(difficulty / 8);
            const remainingBits = difficulty % 8;
            for (let i = 0; i < fullBytes; i++) {
              if (hashBytes[i] !== 0) return false;
            }
            if (remainingBits > 0) {
              const mask = 0xFF << (8 - remainingBits);
              if ((hashBytes[fullBytes] & mask) !== 0) return false;
            }
            return true;
          }

          self.onmessage = async (e) => {
            const { challenge, difficulty } = e.data;
            const nonce = await solve(challenge, difficulty);
            self.postMessage({ nonce });
          };
        `;
        const blob = new Blob([workerCode], {
          type: "application/javascript",
        });
        const worker = new Worker(URL.createObjectURL(blob));
        worker.onmessage = (e) => {
          worker.terminate();
          resolve(e.data.nonce);
        };
        worker.postMessage({ challenge, difficulty });
      });
    },
  };
}
